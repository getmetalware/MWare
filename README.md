# Metalware SDK

Python client SDK for interacting with Metalware [Havoc](https://www.metalware.com/product), a firmware fuzzing platform.

https://i.postimg.cc/bNsmR4cn/project-diagram-2-0-9.png


## Installation

### Using pip

```bash
git clone https://github.com/metalware-inc/metalware-sdk.git
cd metalware-sdk
python3 -m venv venv
. venv/bin/activate
pip install -e .
```

## Usage examples

Make sure to edit `HAVOC_ENDPOINT` to point to the endpoint of the Docker container.

```bash
cd examples/raw_image_multi_rom
python main.py
```
