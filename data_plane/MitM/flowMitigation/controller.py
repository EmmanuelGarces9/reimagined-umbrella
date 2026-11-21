#!/usr/bin/env python3
import argparse
import os
import sys

import grpc

# Para encontrar la librería p4runtime_lib que está en ../../utils/
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections


def writeRules(p4info_helper, sw):
    replicas=[]
    hosts=[
        {"ip" : "10.0.0.1", "mac" : "00:00:00:00:00:01", "port":1},
        {"ip" : "10.0.0.2", "mac" : "00:00:00:00:00:02", "port":2},
        {"ip" : "10.0.0.3", "mac" : "00:00:00:00:00:03", "port":3},
        {"ip" : "10.0.0.4", "mac" : "00:00:00:00:00:04", "port":4},
    ]
    for host in hosts:

        table_entry_fw = p4info_helper.buildTableEntry(
            table_name="MyIngress.mac_forw",
            match_fields={
                "hdr.eth.dstAddr": host["mac"]
                },
            action_name="MyIngress.forward",
            action_params={
                "port": host["port"]
                }
        )
        sw.WriteTableEntry(table_entry_fw)
        replicas.append({"egress_port": host["port"], "instance": 1})
        print("Reglas instaladas para:", host["ip"])
    mc_entry = p4info_helper.buildMulticastGroupEntry(1, replicas) 
    sw.WritePREEntry(mc_entry)


def main(p4info_file_path, bmv2_file_path):
    # Traduce nombres (tablas, acciones) a los IDs que usa P4Runtime
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # 1. Conectarse al switch
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # 2. Declararse controlador principal (obligatorio antes de escribir)
        s1.MasterArbitrationUpdate()

        # 3. Cargar el programa P4 (ojo: esto borra las tablas)
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Programa P4 instalado en s1")

        # 4. Escribir las reglas
        writeRules(p4info_helper, s1)
        print("Reglas instaladas. El switch ya trabaja solo.")

    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='flow_mitigation')
    parser.add_argument('--p4info', type=str,
                        default='./build/flowMitigation.p4.p4info.txtpb')
    parser.add_argument('--bmv2-json', type=str,
                        default='./build/flowMitigation.json')
    args = parser.parse_args()
    main(args.p4info, args.bmv2_json)
