from metalware_sdk import HavocClient
from metalware_sdk.havoc_common_schema import *

PROJECT_NAME="multi-rom-project"
IMAGE_NAME="default"
HAVOC_ENDPOINT="http://localhost:8080" # FIX ME

# Connect to a Havoc server
client = HavocClient(HAVOC_ENDPOINT)

if not client.project_exists(PROJECT_NAME):
  print(f"Creating project {PROJECT_NAME}...")
  # Create a device config.
  device_config = DeviceConfig(memory_layout=[
     Memory(base_addr=0x8000000, size=0x800, memory_type=MemoryType.ROM),
     Memory(base_addr=0x8008000, size=0x100000, memory_type=MemoryType.ROM),
     Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
     Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
  ])

  # Create a project based on the device config.
  client.create_project(
    project_name=PROJECT_NAME,
    config=ProjectConfig(device_config)
  )

if not client.image_exists(PROJECT_NAME, IMAGE_NAME):
  print(f"Creating image {IMAGE_NAME}...")
  # Upload files.
  bootloader_metadata = client.upload_file("bootloader.bin")
  app_metadata = client.upload_file("app.bin")

  # Create RAW image.
  raw_image = RawImage(segments=[
    RawImageSegment(address=0x8000000, hash=bootloader_metadata.hash),
    RawImageSegment(address=0x8008000, hash=app_metadata.hash)
  ])

  image_config = ImageConfig(
    entry_address=0x8000000,
    image_arch=ImageArch.CORTEX_M, 
    image_format=ImageFormat(raw=raw_image)
  )

  client.create_project_image(
    project_name=PROJECT_NAME,
    image_name=IMAGE_NAME,
    image_config=image_config
  )

# Start a dry run to verify configuration.
client.start_run(
  project_name=PROJECT_NAME,
  config=RunConfig(image_name=IMAGE_NAME, dry_run=True)
)

print("Dry run completed successfully.")

#client.start_run(
#  project_name=PROJECT_NAME,
#  config=RunConfig(image_name=IMAGE_NAME, dry_run=False)
#)
