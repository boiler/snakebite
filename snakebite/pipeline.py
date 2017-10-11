# -*- coding: utf-8 -*-
# Copyright (c) 2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

import snakebite.protobuf.ClientNamenodeProtocol_pb2 as client_proto
import snakebite.protobuf.hdfs_pb2 as hdfs_proto
import snakebite.protobuf.datatransfer_pb2 as df_proto
from snakebite.channel import DataXceiverChannel, RpcBufferedReader, get_delimited_message_bytes

import logging
import math
import socket
import struct
import sys
import traceback
import binascii

import google.protobuf.internal.encoder as encoder
import google.protobuf.internal.decoder as decoder

if sys.version_info[0] == 3:
    long = int

log = logging.getLogger(__name__)


class Packet(object):
    def __init__(self, seqno, offset, last):
        self.seqno = seqno
        self.offset = offset
        self.last = last
        self.checksums = []
        self.data = ''

    def __str__(self):
        return 'Packet(seqno={}, offset={}, datalen={})'.format(self.seqno, self.offset, len(self.data))


class BlockStreamWriter(object):
    OUTBOUND_PACKET_SIZE = 65536
    OUTBOUND_CHUNK_SIZE = 512
    ERR_END_OF_BLOCK = -1
    ERR_CLOSED_PIPE = -2
    ERR_ACK_ERROR = -3

    def __init__(self, conn, offset):
        self.conn = conn
        self.offset = offset
        self.seqno = 1
        self.closed = False
        self.ack_error = None
        self.buf = ''

    def write(self, b):
        if self.closed:
            return (0, self.ERR_CLOSED_PIPE)

        if self.ack_error is not None:
            return (0, self.ack_error)

        self.buf += b
        err = self._flush(False)
        return (len(b), err)

    def finish(self):
        if self.closed:
            return None

        self.closed = True
        if self.ack_error is not None:
            return self.ack_error

        err = self._flush(True)
        if err is not None:
            return err

        lastPacket = Packet(self.seqno, self.offset, True)
        self._send_packet(lastPacket)
        err = self._wait_for_acks(lastPacket)
        if err is not None:
            self.ack_error = err
            return err

        return None

    def _flush(self, force):
        err = None

        while len(self.buf) > 0 and (force or len(self.buf) >= self.OUTBOUND_PACKET_SIZE):
            packet = self._make_packet()
            self.offset += len(packet.data)
            self.seqno += 1

            self._send_packet(packet)
            err = self._wait_for_acks(packet)
            if err is not None:
                self.ack_error = err

        return err

    def _make_packet(self):
        packet_length = self.OUTBOUND_PACKET_SIZE
        if len(self.buf) < self.OUTBOUND_PACKET_SIZE:
            packet_length = len(self.buf)

        alignment = self.offset % self.OUTBOUND_CHUNK_SIZE
        if alignment > 0 and packet_length > (self.OUTBOUND_CHUNK_SIZE - alignment):
            packet_length = self.OUTBOUND_CHUNK_SIZE - alignment

        num_chunks = int(math.ceil(float(packet_length) / float(self.OUTBOUND_CHUNK_SIZE)))
        packet = Packet(self.seqno, self.offset, False)
        packet.data += self.buf[:packet_length]
        for i in range(0, num_chunks):
            chunk_off = i * self.OUTBOUND_CHUNK_SIZE
            chunk_end = chunk_off + self.OUTBOUND_CHUNK_SIZE
            if chunk_end >= len(packet.data):
                chunk_end = len(packet.data)

            # a return value of crc32 must be masked because an integer of python is 64bits.
            checksum = binascii.crc32(packet.data[chunk_off:chunk_end]) & 0xffffffff
            packet.checksums.append(checksum)
        self.buf = self.buf[packet_length:]

        return packet

    def _send_packet(self, p):
        headerInfo = df_proto.PacketHeaderProto()
        headerInfo.offsetInBlock = p.offset
        headerInfo.seqno = p.seqno
        headerInfo.lastPacketInBlock = p.last
        headerInfo.dataLen = len(p.data)

        info_bytes = headerInfo.SerializeToString()
        total_length = len(p.data) + len(p.checksums) * 4 + 4
        buf = b''
        buf += struct.pack('!I', total_length)
        buf += struct.pack('!H', len(info_bytes))
        buf += info_bytes

        for checksum in p.checksums:
            buf += struct.pack('!I', checksum)

        buf += p.data
        self.conn.send(buf)

    def _wait_for_acks(self, packet):
        reader = RpcBufferedReader(self.conn)
        nbytes, response_bytes = get_delimited_message_bytes(reader)

        ack = df_proto.PipelineAckProto()
        ack.ParseFromString(response_bytes)
        if ack.seqno != packet.seqno:
            return "Error: invalid seqno"

        all_success = True
        for s in ack.status:
            if s != df_proto.SUCCESS:
                all_success = False

        if not all_success:
            return "ack error seqno={}".format(ack.seqno)

        return None


class BlockWriter(object):

    def __init__(self, block, service, blocksize, use_datanode_hostname):
        self.block = block
        self.service = service
        self.blocksize = blocksize
        self.use_datanode_hostname = use_datanode_hostname

        if self.block.b.numBytes > 0:
            self.offset = block.b.numBytes
            self.append = True
        else:
            self.offset = 0
            self.append = False

        self.closed = False
        self.conn = None
        self.stream = None

    def write(self, b):
        block_full = False
        if self.offset >= self.blocksize:
            return (0, BlockStreamWriter.ERR_END_OF_BLOCK)
        elif (self.offset + len(b)) > self.blocksize:
            block_full = True
            b = b[:(self.blocksize - self.offset)]

        if self.stream is None:
            self._connect_next()

        n, error = self.stream.write(b)
        self.offset += n

        if error is None and block_full:
            error = BLlockStreamWriter.ERR_END_OF_BLOCK

        return (n, error)

    def _get_datanode_address(self, datanode):
        if self.use_datanode_hostname:
            ipaddr = socket.gethostbyname(datanode.id.hostName)
            return (ipaddr, datanode.id.xferPort)
        else:
            return (datanode.id.ipAddr, datanode.id.xferPort)

    def _connect_next(self):
        host, port = self._get_datanode_address(self._current_pipeline()[0])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
        except Exception as e:
            log.error(traceback.format_exc())
            raise
        self.conn = sock

        self._write_block_write_request(sock)
        response = self._read_block_op_response(sock)
        if response.status != df_proto.SUCCESS:
            raise Exception("Error from datanode: {} ({})".format(response.status, response.message))

        self.stream = BlockStreamWriter(sock, self.offset)

    def _read_block_op_response(self, sock):
        buffered_reader = RpcBufferedReader(sock)
        nbytes, response_bytes = get_delimited_message_bytes(buffered_reader)

        response = df_proto.BlockOpResponseProto()
        response.ParseFromString(response_bytes)

        return response

    def _write_block_write_request(self, sock):
        targets = self._current_pipeline()[1:]

        base_header = df_proto.BaseHeaderProto()
        base_header.block.CopyFrom(self.block.b)
        base_header.token.CopyFrom(self.block.blockToken)

        header = df_proto.ClientOperationHeaderProto()
        header.baseHeader.CopyFrom(base_header)
        header.clientName = "snakebite"

        checksum = df_proto.ChecksumProto()
        checksum.type = hdfs_proto.CHECKSUM_CRC32
        checksum.bytesPerChecksum = BlockStreamWriter.OUTBOUND_CHUNK_SIZE

        op = df_proto.OpWriteBlockProto()
        op.header.CopyFrom(header)
        op.targets.extend(targets)
        op.stage = self._current_stage()
        op.pipelineSize = len(targets)
        op.minBytesRcvd = self.block.b.numBytes
        op.maxBytesRcvd = self.offset
        op.latestGenerationStamp = self._generation_stamp()
        op.requestedChecksum.CopyFrom(checksum)
        self._write_block_op_request(sock, DataXceiverChannel.WRITE_BLOCK, op)

    def _write_block_op_request(self, sock, op, msg):
        sock.send(struct.pack('>h', 28))
        sock.send(struct.pack('b', op))
        s_request = msg.SerializeToString()
        sock.send(encoder._VarintBytes(len(s_request)))
        sock.send(s_request)

    def _generation_stamp(self):
        if self.append:
            return self.block.b.generationStamp
        else:
            return 0

    def _current_stage(self):
        if self.append:
            return df_proto.OpWriteBlockProto.PIPELINE_SETUP_APPEND
        else:
            return df_proto.OpWriteBlockProto.PIPELINE_SETUP_CREATE

    def _current_pipeline(self):
        return self.block.locs

    def _finalize_block(self, length):
        self.block.b.numBytes = length
        request = client_proto.UpdateBlockForPipelineRequestProto()
        request.block.CopyFrom(self.block.b)
        request.clientName = "snakebite"
        self.service.updateBlockForPipeline(request)
        return None

    def close(self):
        self.closed = True
        try:
            if self.stream is not None:
                err = self.stream.finish()
                if err is not None:
                    return err

                err = self._finalize_block(self.offset)
                if err is not None:
                    return err
        finally:
            if self.conn is not None:
                self.conn.close()

        return None


class FileWriter(object):
    def __init__(self, service, path, replication, blocksize, file_id, use_datanode_hostname=False):
        self.service = service
        self.path = path
        self.replication = replication
        self.blocksize = blocksize
        self.block_writer = None
        self.file_id = file_id
        self.use_datanode_hostname = use_datanode_hostname

        # LocatedBlockProto
        self.block = None

    def write(self, b):
        log.debug("FileWriter.write bytes({}): {}...".format(len(b), binascii.b2a_hex(b[:10])))
        if self.block_writer is None:
            self._start_new_block()

        written = 0
        while written < len(b):
            n, err = self.block_writer.write(b[written:])
            written += n
            if err is not None:
                if err == BlockStreamWriter.ERR_END_OF_BLOCK:
                    err = self._start_new_block()
                else:
                    break

        return (written, err)

    def _start_new_block(self):
        if self.block_writer is not None:
            self.block_writer.close()

        previous = None
        if self.block is not None:
            previous = self.block.b

        request = client_proto.AddBlockRequestProto()
        request.src = self.path
        request.clientName = "snakebite"
        if previous is not None:
            request.previous.CopyFrom(previous)

        response = self.service.addBlock(request)
        if response is not None:
            self.block = response.block
            self.block_writer = BlockWriter(self.block, self.service, self.blocksize, self.use_datanode_hostname)

    def close(self):
        last_block = None
        if self.block_writer is not None:
            self.block_writer.close()
            last_block = self.block.b

        # Issue a CompleteRequestProto
        request = client_proto.CompleteRequestProto()
        request.src = self.path
        request.fileId = self.file_id
        request.clientName = "snakebite"
        if last_block is not None:
            request.last.CopyFrom(last_block)
        return self.service.complete(request)
