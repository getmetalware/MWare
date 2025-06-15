# Mware

Python client SDK for interacting with Metalware [Havoc](https://www.mware.ink/product), a firmware fuzzing platform.

![image](https://github.com/getmetalware/getmetalware/blob/main/project_diagram.2.0.9.svg)


## Installation

### Using pip

```bash
git clone https://github.com/getmetalware/Mware.git
cd src
python3 -m venv venv
. venv/bin/activate
pip install -e .
```

## Usage examples

Make sure to edit `HAVOC_ENDPOINT` to point to the endpoint of the Docker container.

```bash
cd example/raw_image_multi_rom
python main.py
```
