from enum import Enum
from typing import List, Optional, Any, TypeVar, Callable, Type, cast


T = TypeVar("T")
EnumT = TypeVar("EnumT", bound=Enum)


def from_int(x: Any) -> int:
    assert isinstance(x, int) and not isinstance(x, bool)
    return x


def from_list(f: Callable[[Any], T], x: Any) -> List[T]:
    assert isinstance(x, list)
    return [f(y) for y in x]


def from_none(x: Any) -> Any:
    assert x is None
    return x


def from_str(x: Any) -> str:
    assert isinstance(x, str)
    return x


def from_union(fs, x):
    for f in fs:
        try:
            return f(x)
        except:
            pass
    assert False


def from_bool(x: Any) -> bool:
    assert isinstance(x, bool)
    return x


def to_enum(c: Type[EnumT], x: Any) -> EnumT:
    assert isinstance(x, c)
    return x.value


def to_class(c: Type[T], x: Any) -> dict:
    assert isinstance(x, c)
    return cast(Any, x).to_dict()


class Cwe(Enum):
    IMPROPER_CHECK_FOR_UNUSUAL_CONDITIONS = "ImproperCheckForUnusualConditions"
    NULL_POINTER_DEREFERENCE = "NullPointerDereference"
    OUT_OF_BOUNDS_WRITE = "OutOfBoundsWrite"


class Event:
    block_id: int
    callstack: List[int]
    dwarf_stack_trace: Optional[str]
    label: str
    pc: int

    def __init__(self, block_id: int, callstack: List[int], dwarf_stack_trace: Optional[str], label: str, pc: int) -> None:
        self.block_id = block_id
        self.callstack = callstack
        self.dwarf_stack_trace = dwarf_stack_trace
        self.label = label
        self.pc = pc

    @staticmethod
    def from_dict(obj: Any) -> 'Event':
        assert isinstance(obj, dict)
        block_id = from_int(obj.get("block_id"))
        callstack = from_list(from_int, obj.get("callstack"))
        dwarf_stack_trace = from_union([from_none, from_str], obj.get("dwarf_stack_trace"))
        label = from_str(obj.get("label"))
        pc = from_int(obj.get("pc"))
        return Event(block_id, callstack, dwarf_stack_trace, label, pc)

    def to_dict(self) -> dict:
        result: dict = {}
        result["block_id"] = from_int(self.block_id)
        result["callstack"] = from_list(from_int, self.callstack)
        if self.dwarf_stack_trace is not None:
            result["dwarf_stack_trace"] = from_union([from_none, from_str], self.dwarf_stack_trace)
        result["label"] = from_str(self.label)
        result["pc"] = from_int(self.pc)
        return result


class ClassifiedCrash:
    cwes: List[Cwe]
    events: List[Event]
    suspected_false_positive: bool
    taint_trace: str

    def __init__(self, cwes: List[Cwe], events: List[Event], suspected_false_positive: bool, taint_trace: str) -> None:
        self.cwes = cwes
        self.events = events
        self.suspected_false_positive = suspected_false_positive
        self.taint_trace = taint_trace

    @staticmethod
    def from_dict(obj: Any) -> 'ClassifiedCrash':
        assert isinstance(obj, dict)
        cwes = from_list(Cwe, obj.get("cwes"))
        events = from_list(Event.from_dict, obj.get("events"))
        suspected_false_positive = from_bool(obj.get("suspected_false_positive"))
        taint_trace = from_str(obj.get("taint_trace"))
        return ClassifiedCrash(cwes, events, suspected_false_positive, taint_trace)

    def to_dict(self) -> dict:
        result: dict = {}
        result["cwes"] = from_list(lambda x: to_enum(Cwe, x), self.cwes)
        result["events"] = from_list(lambda x: to_class(Event, x), self.events)
        result["suspected_false_positive"] = from_bool(self.suspected_false_positive)
        result["taint_trace"] = from_str(self.taint_trace)
        return result


class UnclassifiedCrash:
    callstack: List[int]
    classification_failure: str
    label: str

    def __init__(self, callstack: List[int], classification_failure: str, label: str) -> None:
        self.callstack = callstack
        self.classification_failure = classification_failure
        self.label = label

    @staticmethod
    def from_dict(obj: Any) -> 'UnclassifiedCrash':
        assert isinstance(obj, dict)
        callstack = from_list(from_int, obj.get("callstack"))
        classification_failure = from_str(obj.get("classification_failure"))
        label = from_str(obj.get("label"))
        return UnclassifiedCrash(callstack, classification_failure, label)

    def to_dict(self) -> dict:
        result: dict = {}
        result["callstack"] = from_list(from_int, self.callstack)
        result["classification_failure"] = from_str(self.classification_failure)
        result["label"] = from_str(self.label)
        return result


class AnalysisResult:
    classified_crash: Optional[ClassifiedCrash]
    unclassified_crash: Optional[UnclassifiedCrash]

    def __init__(self, classified_crash: Optional[ClassifiedCrash], unclassified_crash: Optional[UnclassifiedCrash]) -> None:
        self.classified_crash = classified_crash
        self.unclassified_crash = unclassified_crash

    @staticmethod
    def from_dict(obj: Any) -> 'AnalysisResult':
        assert isinstance(obj, dict)
        classified_crash = from_union([ClassifiedCrash.from_dict, from_none], obj.get("ClassifiedCrash"))
        unclassified_crash = from_union([UnclassifiedCrash.from_dict, from_none], obj.get("UnclassifiedCrash"))
        return AnalysisResult(classified_crash, unclassified_crash)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.classified_crash is not None:
            result["ClassifiedCrash"] = from_union([lambda x: to_class(ClassifiedCrash, x), from_none], self.classified_crash)
        if self.unclassified_crash is not None:
            result["UnclassifiedCrash"] = from_union([lambda x: to_class(UnclassifiedCrash, x), from_none], self.unclassified_crash)
        return result


class MemoryFileSegment:
    """MemoryConfig
    
    For ELFs: .------- ELF file ------------. .-----------------------------.       |
    .--------------------.    | |  ROM                        |---------->| ELF Segment
    1      |    | 0x80000000 '--------- Memory    ---------'\      |
    '--------------------'    | |                               \     |
    .--------------------.    | .-----------------------------.  '------->| ELF Segment
    2      |    | 0x80000dec |  R*M                        |       |
    '--------------------'    | '--------- Memory    ---------' -.    |
    .--------------------.    | '------->| ELF Segment 3      |    | 0x10000000 |
    '--------------------'    | '-----------------------------'
    
    For stripped images: .-----------------------------.           .--------------------. |
    ROM                        |---------->| stripped.bin       | '--------- Memory
    ------------'           '--------------------' | .-----------------------------. |
    RAM                        | '--------- Memory ------------'
    """
    file_offset: int
    memory_offset: int
    size: int

    def __init__(self, file_offset: int, memory_offset: int, size: int) -> None:
        self.file_offset = file_offset
        self.memory_offset = memory_offset
        self.size = size

    @staticmethod
    def from_dict(obj: Any) -> 'MemoryFileSegment':
        assert isinstance(obj, dict)
        file_offset = from_int(obj.get("file_offset"))
        memory_offset = from_int(obj.get("memory_offset"))
        size = from_int(obj.get("size"))
        return MemoryFileSegment(file_offset, memory_offset, size)

    def to_dict(self) -> dict:
        result: dict = {}
        result["file_offset"] = from_int(self.file_offset)
        result["memory_offset"] = from_int(self.memory_offset)
        result["size"] = from_int(self.size)
        return result


class MemoryFile:
    path: str
    segments: List[MemoryFileSegment]

    def __init__(self, path: str, segments: List[MemoryFileSegment]) -> None:
        self.path = path
        self.segments = segments

    @staticmethod
    def from_dict(obj: Any) -> 'MemoryFile':
        assert isinstance(obj, dict)
        path = from_str(obj.get("path"))
        segments = from_list(MemoryFileSegment.from_dict, obj.get("segments"))
        return MemoryFile(path, segments)

    def to_dict(self) -> dict:
        result: dict = {}
        result["path"] = from_str(self.path)
        result["segments"] = from_list(lambda x: to_class(MemoryFileSegment, x), self.segments)
        return result


class MemoryType(Enum):
    MMIO = "mmio"
    RAM = "ram"
    ROM = "rom"


class Memory:
    aliased_to: Optional[int]
    base_addr: int
    file: Optional[MemoryFile]
    fill: Optional[int]
    memory_type: MemoryType
    size: int

    #def __init__(self, aliased_to: Optional[int], base_addr: int, file: Optional[MemoryFile], fill: Optional[int], memory_type: MemoryType, size: int) -> None:
    def __init__(self, base_addr: int, size: int, memory_type: MemoryType, aliased_to: Optional[int] = None, file: Optional[MemoryFile] = None, fill: Optional[int] = None) -> None:
        self.base_addr = base_addr
        self.size = size
        self.memory_type = memory_type
        self.aliased_to = aliased_to
        self.file = file
        self.fill = fill

    @staticmethod
    def from_dict(obj: Any) -> 'Memory':
        assert isinstance(obj, dict)
        aliased_to = from_union([from_none, from_int], obj.get("aliased_to"))
        base_addr = from_int(obj.get("base_addr"))
        file = from_union([MemoryFile.from_dict, from_none], obj.get("file"))
        fill = from_union([from_none, from_int], obj.get("fill"))
        memory_type = MemoryType(obj.get("memory_type"))
        size = from_int(obj.get("size"))
        return Memory(base_addr, size, memory_type, aliased_to, file, fill)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.aliased_to is not None:
            result["aliased_to"] = from_union([from_none, from_int], self.aliased_to)
        result["base_addr"] = from_int(self.base_addr)
        if self.file is not None:
            result["file"] = from_union([lambda x: to_class(MemoryFile, x), from_none], self.file)
        if self.fill is not None:
            result["fill"] = from_union([from_none, from_int], self.fill)
        result["memory_type"] = to_enum(MemoryType, self.memory_type)
        result["size"] = from_int(self.size)
        return result


class DeviceConfig:
    memory_layout: List[Memory]

    def __init__(self, memory_layout: List[Memory]) -> None:
        self.memory_layout = memory_layout

    @staticmethod
    def from_dict(obj: Any) -> 'DeviceConfig':
        assert isinstance(obj, dict)
        memory_layout = from_list(Memory.from_dict, obj.get("memory_layout"))
        return DeviceConfig(memory_layout)

    def to_dict(self) -> dict:
        result: dict = {}
        result["memory_layout"] = from_list(lambda x: to_class(Memory, x), self.memory_layout)
        return result

# process
class FileMetadata:
    hash: str
    is_elf: bool
    size: int

    def __init__(self, hash: str, is_elf: bool, size: int) -> None:
        self.hash = hash
        self.is_elf = is_elf
        self.size = size

    @staticmethod
    def from_dict(obj: Any) -> 'FileMetadata':
        assert isinstance(obj, dict)
        hash = from_str(obj.get("hash"))
        is_elf = from_bool(obj.get("is_elf"))
        size = from_int(obj.get("size"))
        return FileMetadata(hash, is_elf, size)

    def to_dict(self) -> dict:
        result: dict = {}
        result["hash"] = from_str(self.hash)
        result["is_elf"] = from_bool(self.is_elf)
        result["size"] = from_int(self.size)
        return result


class FormatMemoryLayoutRequest:
    image_hash: str
    memory_layout: List[Memory]

    def __init__(self, image_hash: str, memory_layout: List[Memory]) -> None:
        self.image_hash = image_hash
        self.memory_layout = memory_layout

    @staticmethod
    def from_dict(obj: Any) -> 'FormatMemoryLayoutRequest':
        assert isinstance(obj, dict)
        image_hash = from_str(obj.get("image_hash"))
        memory_layout = from_list(Memory.from_dict, obj.get("memory_layout"))
        return FormatMemoryLayoutRequest(image_hash, memory_layout)

    def to_dict(self) -> dict:
        result: dict = {}
        result["image_hash"] = from_str(self.image_hash)
        result["memory_layout"] = from_list(lambda x: to_class(Memory, x), self.memory_layout)
        return result


class ImageArch(Enum):
    CORTEX_M = "CortexM"


class RawImageSegment:
    address: int
    hash: str

    def __init__(self, address: int, hash: str) -> None:
        self.address = address
        self.hash = hash

    @staticmethod
    def from_dict(obj: Any) -> 'RawImageSegment':
        assert isinstance(obj, dict)
        address = from_int(obj.get("address"))
        hash = from_str(obj.get("hash"))
        return RawImageSegment(address, hash)

    def to_dict(self) -> dict:
        result: dict = {}
        result["address"] = from_int(self.address)
        result["hash"] = from_str(self.hash)
        return result


class RawImage:
    segments: List[RawImageSegment]

    def __init__(self, segments: List[RawImageSegment]) -> None:
        self.segments = segments

    @staticmethod
    def from_dict(obj: Any) -> 'RawImage':
        assert isinstance(obj, dict)
        segments = from_list(RawImageSegment.from_dict, obj.get("segments"))
        return RawImage(segments)

    def to_dict(self) -> dict:
        result: dict = {}
        result["segments"] = from_list(lambda x: to_class(RawImageSegment, x), self.segments)
        return result


class ImageFormat:
    elf: Optional[str]
    raw: Optional[RawImage]

    def __init__(self, elf: Optional[str] = None, raw: Optional[RawImage] = None) -> None:
        self.elf = elf
        self.raw = raw

    @staticmethod
    def from_dict(obj: Any) -> 'ImageFormat':
        assert isinstance(obj, dict)
        elf = from_union([from_str, from_none], obj.get("Elf"))
        raw = from_union([RawImage.from_dict, from_none], obj.get("Raw"))
        return ImageFormat(elf, raw)

    def to_dict(self) -> dict:
        result: dict = {}
        if self.elf is not None:
            result["Elf"] = from_union([from_str, from_none], self.elf)
        if self.raw is not None:
            result["Raw"] = from_union([lambda x: to_class(RawImage, x), from_none], self.raw)
        return result


class PatchType(Enum):
    NOP = "Nop"
    RETURN = "Return"
    RETURN0 = "Return0"
    RETURN1 = "Return1"


class Patch:
    address: int
    patch_type: PatchType

    def __init__(self, address: int, patch_type: PatchType) -> None:
        self.address = address
        self.patch_type = patch_type

    @staticmethod
    def from_dict(obj: Any) -> 'Patch':
        assert isinstance(obj, dict)
        address = from_int(obj.get("address"))
        patch_type = PatchType(obj.get("patch_type"))
        return Patch(address, patch_type)

    def to_dict(self) -> dict:
        result: dict = {}
        result["address"] = from_int(self.address)
        result["patch_type"] = to_enum(PatchType, self.patch_type)
        return result

class Symbol:
    address: int
    name: str
    size: int

    def __init__(self, address: int, name: str, size: int) -> None:
        self.address = address
        self.name = name
        self.size = size

    @staticmethod
    def from_dict(obj: Any) -> 'Symbol':
        assert isinstance(obj, dict)
        address = from_int(obj.get("address"))
        name = from_str(obj.get("name"))
        size = from_int(obj.get("size"))
        return Symbol(address, name, size)

    def to_dict(self) -> dict:
        result: dict = {}
        result["address"] = from_int(self.address)
        result["name"] = from_str(self.name)
        result["size"] = from_int(self.size)
        return result

class ImageConfig:
    entry_address: int
    image_arch: ImageArch
    image_format: ImageFormat
    patches: List[Patch]
    symbols: List[Symbol]

    def __init__(self, entry_address: int, image_arch: ImageArch, image_format: ImageFormat, patches: List[Patch] = [], symbols: List[Symbol] = []) -> None:
        self.entry_address = entry_address
        self.image_arch = image_arch
        self.image_format = image_format
        self.patches = patches
        self.symbols = symbols

    @staticmethod
    def from_dict(obj: Any) -> 'ImageConfig':
        assert isinstance(obj, dict)
        entry_address = from_int(obj.get("entry_address"))
        image_arch = ImageArch(obj.get("image_arch"))
        image_format = ImageFormat.from_dict(obj.get("image_format"))
        patches = from_list(Patch.from_dict, obj.get("patches"))
        symbols = from_list(Symbol.from_dict, obj.get("symbols"))
        return ImageConfig(entry_address, image_arch, image_format, patches, symbols)

    def to_dict(self) -> dict:
        result: dict = {}
        result["entry_address"] = from_int(self.entry_address)
        result["image_arch"] = to_enum(ImageArch, self.image_arch)
        result["image_format"] = to_class(ImageFormat, self.image_format)
        result["patches"] = from_list(lambda x: to_class(Patch, x), self.patches)
        result["symbols"] = from_list(lambda x: to_class(Symbol, x), self.symbols)
        return result


class InferredConfig:
    device_config: DeviceConfig
    image_config: ImageConfig

    def __init__(self, device_config: DeviceConfig, image_config: ImageConfig) -> None:
        self.device_config = device_config
        self.image_config = image_config

    @staticmethod
    def from_dict(obj: Any) -> 'InferredConfig':
        assert isinstance(obj, dict)
        device_config = DeviceConfig.from_dict(obj.get("device_config"))
        image_config = ImageConfig.from_dict(obj.get("image_config"))
        return InferredConfig(device_config, image_config)

    def to_dict(self) -> dict:
        result: dict = {}
        result["device_config"] = to_class(DeviceConfig, self.device_config)
        result["image_config"] = to_class(ImageConfig, self.image_config)
        return result


class FuzzerConfig:
    fuzz_consumption_timeout: int
    interrupt_interval: int

    def __init__(self, fuzz_consumption_timeout: int, interrupt_interval: int) -> None:
        self.fuzz_consumption_timeout = fuzz_consumption_timeout
        self.interrupt_interval = interrupt_interval

    @staticmethod
    def from_dict(obj: Any) -> 'FuzzerConfig':
        assert isinstance(obj, dict)
        fuzz_consumption_timeout = from_int(obj.get("fuzz_consumption_timeout"))
        interrupt_interval = from_int(obj.get("interrupt_interval"))
        return FuzzerConfig(fuzz_consumption_timeout, interrupt_interval)

    def to_dict(self) -> dict:
        result: dict = {}
        result["fuzz_consumption_timeout"] = from_int(self.fuzz_consumption_timeout)
        result["interrupt_interval"] = from_int(self.interrupt_interval)
        return result


class ProjectConfig:
    device_config: DeviceConfig
    fuzzer_config: Optional[FuzzerConfig]

    def __init__(self, device_config: DeviceConfig, fuzzer_config: Optional[FuzzerConfig] = None) -> None:
        self.device_config = device_config
        self.fuzzer_config = fuzzer_config

    @staticmethod
    def from_dict(obj: Any) -> 'ProjectConfig':
        assert isinstance(obj, dict)
        device_config = DeviceConfig.from_dict(obj.get("device_config"))
        fuzzer_config = from_union([FuzzerConfig.from_dict, from_none], obj.get("fuzzer_config"))
        return ProjectConfig(device_config, fuzzer_config)

    def to_dict(self) -> dict:
        result: dict = {}
        result["device_config"] = to_class(DeviceConfig, self.device_config)
        if self.fuzzer_config is not None:
            result["fuzzer_config"] = from_union([lambda x: to_class(FuzzerConfig, x), from_none], self.fuzzer_config)
        return result


class RunConfig:
    dry_run: bool
    fuzzer_config: Optional[FuzzerConfig]
    image_name: str
    instance_count: int

    def __init__(self, image_name: str, instance_count: int = 1, dry_run: bool = False, fuzzer_config: Optional[FuzzerConfig] = None) -> None:
        self.dry_run = dry_run
        self.fuzzer_config = fuzzer_config
        self.image_name = image_name
        self.instance_count = instance_count

    @staticmethod
    def from_dict(obj: Any) -> 'RunConfig':
        assert isinstance(obj, dict)
        dry_run = from_bool(obj.get("dry_run"))
        fuzzer_config = from_union([FuzzerConfig.from_dict, from_none], obj.get("fuzzer_config"))
        image_name = from_str(obj.get("image_name"))
        instance_count = from_int(obj.get("instance_count"))
        return RunConfig(image_name, instance_count, dry_run, fuzzer_config)

    def to_dict(self) -> dict:
        result: dict = {}
        result["dry_run"] = from_bool(self.dry_run)
        if self.fuzzer_config is not None:
            result["fuzzer_config"] = from_union([lambda x: to_class(FuzzerConfig, x), from_none], self.fuzzer_config)
        result["image_name"] = from_str(self.image_name)
        result["instance_count"] = from_int(self.instance_count)
        return result


class Crash:
    id: str
    result: AnalysisResult

    def __init__(self, id: str, result: AnalysisResult) -> None:
        self.id = id
        self.result = result

    @staticmethod
    def from_dict(obj: Any) -> 'Crash':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        result = AnalysisResult.from_dict(obj.get("result"))
        return Crash(id, result)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["result"] = to_class(AnalysisResult, self.result)
        return result


class DefectMetadata:
    callstack: List[int]
    count: int
    exit: str
    id: str

    def __init__(self, callstack: List[int], count: int, exit: str, id: str) -> None:
        self.callstack = callstack
        self.count = count
        self.exit = exit
        self.id = id

    @staticmethod
    def from_dict(obj: Any) -> 'DefectMetadata':
        assert isinstance(obj, dict)
        callstack = from_list(from_int, obj.get("callstack"))
        count = from_int(obj.get("count"))
        exit = from_str(obj.get("exit"))
        id = from_str(obj.get("id"))
        return DefectMetadata(callstack, count, exit, id)

    def to_dict(self) -> dict:
        result: dict = {}
        result["callstack"] = from_list(from_int, self.callstack)
        result["count"] = from_int(self.count)
        result["exit"] = from_str(self.exit)
        result["id"] = from_str(self.id)
        return result


class Hang:
    id: str
    result: DefectMetadata

    def __init__(self, id: str, result: DefectMetadata) -> None:
        self.id = id
        self.result = result

    @staticmethod
    def from_dict(obj: Any) -> 'Hang':
        assert isinstance(obj, dict)
        id = from_str(obj.get("id"))
        result = DefectMetadata.from_dict(obj.get("result"))
        return Hang(id, result)

    def to_dict(self) -> dict:
        result: dict = {}
        result["id"] = from_str(self.id)
        result["result"] = to_class(DefectMetadata, self.result)
        return result


class Block:
    address: int
    time_to_discover: int

    def __init__(self, address: int, time_to_discover: int) -> None:
        self.address = address
        self.time_to_discover = time_to_discover

    @staticmethod
    def from_dict(obj: Any) -> 'Block':
        assert isinstance(obj, dict)
        address = from_int(obj.get("address"))
        time_to_discover = from_int(obj.get("time_to_discover"))
        return Block(address, time_to_discover)

    def to_dict(self) -> dict:
        result: dict = {}
        result["address"] = from_int(self.address)
        result["time_to_discover"] = from_int(self.time_to_discover)
        return result


class RunStats:
    block_frequency_map: List[List[int]]
    coverage: List[List[int]]
    crashes: List[Crash]
    executions: int
    hangs: List[Hang]
    new_blocks: List[Block]
    throughput: int

    def __init__(self, block_frequency_map: List[List[int]], coverage: List[List[int]], crashes: List[Crash], executions: int, hangs: List[Hang], new_blocks: List[Block], throughput: int) -> None:
        self.block_frequency_map = block_frequency_map
        self.coverage = coverage
        self.crashes = crashes
        self.executions = executions
        self.hangs = hangs
        self.new_blocks = new_blocks
        self.throughput = throughput

    @staticmethod
    def from_dict(obj: Any) -> 'RunStats':
        assert isinstance(obj, dict)
        block_frequency_map = from_list(lambda x: from_list(from_int, x), obj.get("block_frequency_map"))
        coverage = from_list(lambda x: from_list(from_int, x), obj.get("coverage"))
        crashes = from_list(Crash.from_dict, obj.get("crashes"))
        executions = from_int(obj.get("executions"))
        hangs = from_list(Hang.from_dict, obj.get("hangs"))
        new_blocks = from_list(Block.from_dict, obj.get("new_blocks"))
        throughput = from_int(obj.get("throughput"))
        return RunStats(block_frequency_map, coverage, crashes, executions, hangs, new_blocks, throughput)

    def to_dict(self) -> dict:
        result: dict = {}
        result["block_frequency_map"] = from_list(lambda x: from_list(from_int, x), self.block_frequency_map)
        result["coverage"] = from_list(lambda x: from_list(from_int, x), self.coverage)
        result["crashes"] = from_list(lambda x: to_class(Crash, x), self.crashes)
        result["executions"] = from_int(self.executions)
        result["hangs"] = from_list(lambda x: to_class(Hang, x), self.hangs)
        result["new_blocks"] = from_list(lambda x: to_class(Block, x), self.new_blocks)
        result["throughput"] = from_int(self.throughput)
        return result


class RunStatus(Enum):
    CRASHED = "Crashed"
    ERROR = "Error"
    FINISHED = "Finished"
    PENDING = "Pending"
    RUNNING = "Running"


class RunSummary:
    created_at: int
    modified_at: int
    status: RunStatus

    def __init__(self, created_at: int, modified_at: int, status: RunStatus) -> None:
        self.created_at = created_at
        self.modified_at = modified_at
        self.status = status

    @staticmethod
    def from_dict(obj: Any) -> 'RunSummary':
        assert isinstance(obj, dict)
        created_at = from_int(obj.get("created_at"))
        modified_at = from_int(obj.get("modified_at"))
        status = RunStatus(obj.get("status"))
        return RunSummary(created_at, modified_at, status)

    def to_dict(self) -> dict:
        result: dict = {}
        result["created_at"] = from_int(self.created_at)
        result["modified_at"] = from_int(self.modified_at)
        result["status"] = to_enum(RunStatus, self.status)
        return result


class Symbol:
    address: int
    name: str
    size: int

    def __init__(self, address: int, name: str, size: int) -> None:
        self.address = address
        self.name = name
        self.size = size

    @staticmethod
    def from_dict(obj: Any) -> 'Symbol':
        assert isinstance(obj, dict)
        address = from_int(obj.get("address"))
        name = from_str(obj.get("name"))
        size = from_int(obj.get("size"))
        return Symbol(address, name, size)

    def to_dict(self) -> dict:
        result: dict = {}
        result["address"] = from_int(self.address)
        result["name"] = from_str(self.name)
        result["size"] = from_int(self.size)
        return result


class TraceSummaryEntry:
    exit_pc: int
    exit_reason: str
    input_label: str
    num_blocks: int
    timestamp: str

    def __init__(self, exit_pc: int, exit_reason: str, input_label: str, num_blocks: int, timestamp: str) -> None:
        self.exit_pc = exit_pc
        self.exit_reason = exit_reason
        self.input_label = input_label
        self.num_blocks = num_blocks
        self.timestamp = timestamp

    @staticmethod
    def from_dict(obj: Any) -> 'TraceSummaryEntry':
        assert isinstance(obj, dict)
        exit_pc = from_int(obj.get("exit_pc"))
        exit_reason = from_str(obj.get("exit_reason"))
        input_label = from_str(obj.get("input_label"))
        num_blocks = from_int(obj.get("num_blocks"))
        timestamp = from_str(obj.get("timestamp"))
        return TraceSummaryEntry(exit_pc, exit_reason, input_label, num_blocks, timestamp)

    def to_dict(self) -> dict:
        result: dict = {}
        result["exit_pc"] = from_int(self.exit_pc)
        result["exit_reason"] = from_str(self.exit_reason)
        result["input_label"] = from_str(self.input_label)
        result["num_blocks"] = from_int(self.num_blocks)
        result["timestamp"] = from_str(self.timestamp)
        return result


class TraceSummary:
    entries: List[TraceSummaryEntry]

    def __init__(self, entries: List[TraceSummaryEntry]) -> None:
        self.entries = entries

    @staticmethod
    def from_dict(obj: Any) -> 'TraceSummary':
        assert isinstance(obj, dict)
        entries = from_list(TraceSummaryEntry.from_dict, obj.get("entries"))
        return TraceSummary(entries)

    def to_dict(self) -> dict:
        result: dict = {}
        result["entries"] = from_list(lambda x: to_class(TraceSummaryEntry, x), self.entries)
        return result


class UploadImageRequest:
    label: str
    payload: List[int]

    def __init__(self, label: str, payload: List[int]) -> None:
        self.label = label
        self.payload = payload

    @staticmethod
    def from_dict(obj: Any) -> 'UploadImageRequest':
        assert isinstance(obj, dict)
        label = from_str(obj.get("label"))
        payload = from_list(from_int, obj.get("payload"))
        return UploadImageRequest(label, payload)

    def to_dict(self) -> dict:
        result: dict = {}
        result["label"] = from_str(self.label)
        result["payload"] = from_list(from_int, self.payload)
        return result


class HavocCommonSchema:
    analysis_result: AnalysisResult
    classified_crash: ClassifiedCrash
    device_config: DeviceConfig
    file_metadata: FileMetadata
    format_memory_layout_request: FormatMemoryLayoutRequest
    image: ImageConfig
    inference_response: InferredConfig
    project_config: ProjectConfig
    run_config: RunConfig
    run_stats: RunStats
    run_summary: RunSummary
    symbol: Symbol
    trace_summary: TraceSummary
    unclassified_crash: UnclassifiedCrash
    upload_image_request: UploadImageRequest

    def __init__(self, analysis_result: AnalysisResult, classified_crash: ClassifiedCrash, device_config: DeviceConfig, file_metadata: FileMetadata, format_memory_layout_request: FormatMemoryLayoutRequest, image: ImageConfig, inference_response: InferredConfig, project_config: ProjectConfig, run_config: RunConfig, run_stats: RunStats, run_summary: RunSummary, symbol: Symbol, trace_summary: TraceSummary, unclassified_crash: UnclassifiedCrash, upload_image_request: UploadImageRequest) -> None:
        self.analysis_result = analysis_result
        self.classified_crash = classified_crash
        self.device_config = device_config
        self.file_metadata = file_metadata
        self.format_memory_layout_request = format_memory_layout_request
        self.image = image
        self.inference_response = inference_response
        self.project_config = project_config
        self.run_config = run_config
        self.run_stats = run_stats
        self.run_summary = run_summary
        self.symbol = symbol
        self.trace_summary = trace_summary
        self.unclassified_crash = unclassified_crash
        self.upload_image_request = upload_image_request

    @staticmethod
    def from_dict(obj: Any) -> 'HavocCommonSchema':
        assert isinstance(obj, dict)
        analysis_result = AnalysisResult.from_dict(obj.get("analysis_result"))
        classified_crash = ClassifiedCrash.from_dict(obj.get("classified_crash"))
        device_config = DeviceConfig.from_dict(obj.get("device_config"))
        file_metadata = FileMetadata.from_dict(obj.get("file_metadata"))
        format_memory_layout_request = FormatMemoryLayoutRequest.from_dict(obj.get("format_memory_layout_request"))
        image = ImageConfig.from_dict(obj.get("image"))
        inference_response = InferredConfig.from_dict(obj.get("inference_response"))
        project_config = ProjectConfig.from_dict(obj.get("project_config"))
        run_config = RunConfig.from_dict(obj.get("run_config"))
        run_stats = RunStats.from_dict(obj.get("run_stats"))
        run_summary = RunSummary.from_dict(obj.get("run_summary"))
        symbol = Symbol.from_dict(obj.get("symbol"))
        trace_summary = TraceSummary.from_dict(obj.get("trace_summary"))
        unclassified_crash = UnclassifiedCrash.from_dict(obj.get("unclassified_crash"))
        upload_image_request = UploadImageRequest.from_dict(obj.get("upload_image_request"))
        return HavocCommonSchema(analysis_result, classified_crash, device_config, file_metadata, format_memory_layout_request, image, inference_response, project_config, run_config, run_stats, run_summary, symbol, trace_summary, unclassified_crash, upload_image_request)

    def to_dict(self) -> dict:
        result: dict = {}
        result["analysis_result"] = to_class(AnalysisResult, self.analysis_result)
        result["classified_crash"] = to_class(ClassifiedCrash, self.classified_crash)
        result["device_config"] = to_class(DeviceConfig, self.device_config)
        result["file_metadata"] = to_class(FileMetadata, self.file_metadata)
        result["format_memory_layout_request"] = to_class(FormatMemoryLayoutRequest, self.format_memory_layout_request)
        result["image"] = to_class(ImageConfig, self.image)
        result["inference_response"] = to_class(InferredConfig, self.inference_response)
        result["project_config"] = to_class(ProjectConfig, self.project_config)
        result["run_config"] = to_class(RunConfig, self.run_config)
        result["run_stats"] = to_class(RunStats, self.run_stats)
        result["run_summary"] = to_class(RunSummary, self.run_summary)
        result["symbol"] = to_class(Symbol, self.symbol)
        result["trace_summary"] = to_class(TraceSummary, self.trace_summary)
        result["unclassified_crash"] = to_class(UnclassifiedCrash, self.unclassified_crash)
        result["upload_image_request"] = to_class(UploadImageRequest, self.upload_image_request)
        return result


def havoc_common_schema_from_dict(s: Any) -> HavocCommonSchema:
    return HavocCommonSchema.from_dict(s)


def havoc_common_schema_to_dict(x: HavocCommonSchema) -> Any:
    return to_class(HavocCommonSchema, x)
