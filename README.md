# Archer Fuzzer
![](img/image.jpg)

## Description
Archer is a Python3 network fuzzer focused on Remote Desktop Protocol (RDP). It uses mutation based fuzzing (via Radama through `pyradamsa`) against 
RDP client messages to discover crashes. The objective is to trigger unexpected states, crashes or hangs in the ta


## Requirements
- Python 3.x
- `pyradamsa` (Python bindings for Radamsa | Only available on Linux)
- A reachable RDP service to fuzz (test instances / lab only)

Direct:
```bash
pip3 install pyradamsa
``` 
Requirement File:
```bash
python3 -m pip install -r requirements.txt
```

## Usage

#### Basic Usage
```bash
python3 archer.py <HOST> <SEED_FILE>
```
- `HOST`: IP Address or hostname of the target RDP server
- `SEED_FILE`: Path to a captured ClientHello that will be used as the base for mutations

#### Example Script Commandline
```bash
python3 archer.py 192.168.56.10 money.dat
```