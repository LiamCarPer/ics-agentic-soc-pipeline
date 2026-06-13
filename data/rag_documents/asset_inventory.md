# Asset Inventory

## plc-intake (172.21.0.10)

The intake PLC controls the water intake process in the OT-Security-Lab. It manages the inlet valve (reg_0) and reports tank level (reg_5) for the raw water holding tank. This is a Critical asset in the Level 1 Control Zone running OpenPLC v4 firmware 4.0.7. It communicates via Modbus TCP on port 502. The HMI (172.22.0.10) polls it every 5 seconds for register data, and the engineering workstation (172.23.0.4) is the only authorized source for Modbus write commands (FC 6, FC 16).

## plc-treatment (172.21.0.11)

The treatment PLC manages chemical dosing and filtration for the water treatment process. It is a sibling PLC at the same security zone level as plc-intake. Under normal operation it is contacted only by the HMI for reads. This asset is relevant during scanning anomalies where an attacker probes multiple PLCs in quick succession.

## plc-distribution (172.21.0.12)

The distribution PLC manages the water tower and distribution pumps. Like plc-treatment, it is a sibling PLC contacted only by the HMI under normal conditions. It runs the same OpenPLC v4 firmware. Anomalous traffic to this asset from unrecognized IPs indicates lateral movement or network reconnaissance.

## ot-hmi (172.22.0.10)

The SCADA Human-Machine Interface (HMI) is the primary operator interface for the water treatment process. It is authorized to read registers from all three PLCs (FC 3) but must never issue write commands. The HMI is located in the Level 2 Supervisory Control zone. Its IP is treated as a known-good read-only source. Any write command originating from this IP is suspicious and may indicate a compromised HMI or an attacker using its identity.

## eng-ws-01 (172.23.0.4)

The Engineering Workstation is the sole authorized source for Modbus write commands (FC 6, FC 16) to the PLCs. It is located in a physically secured area with access control. Under normal operation it writes only during maintenance windows or process setpoint changes. Any write from an IP other than this workstation is considered an unauthorized write anomaly.
