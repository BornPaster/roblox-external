import time
import json
import struct
import psutil
import ctypes
import win32gui
import win32con
import traceback
import win32process

from ctypes import wintypes


with open('offsets.json', 'r') as f:
    OFFSETS = json.load(f)


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32Usage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.DWORD)),
        ("th32ModuleID", wintypes.DWORD),
        ("th32Threads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260)
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260)
    ]

class vec2:
    def __init__(self, x=0.0, y=0.0):
        self.x = x
        self.y = y

class vec3:
    def __init__(self, x=0.0, y=0.0, z=0.0):
        self.x = x
        self.y = y
        self.z = z

class robloxmemory:
    def __init__(self):
        self.process_handle = None
        self.process_id = None
        self.base_address = None
        self.data_model = None
        self.players = None
        self.local_player = None
        self.workspace = None
        self.camera = None
        self.visual_engine = None
        self.fake_data_model = None
        self.data_model_pointer = None
        self.hwnd = None
        self.cache = {}
        self.cache_timeout = 0.5
        self.last_cache_clear = time.time()
        self.cache_hits = 0
        self.cache_misses = 0
        self.kernel32 = ctypes.windll.kernel32
        self.locked_target = None
        if not self.find_roblox_process():
            raise Exception("failed to find roblox process.")
        self.initialize_game_data()

    def get_cached(self, key, timeout=None):
        if timeout is None:
            timeout = self.cache_timeout
        if key in self.cache:
            value, timestamp = self.cache[key]
            if time.time() - timestamp < timeout:
                self.cache_hits += 1
                return value
            else:
                del self.cache[key]
                self.cache_misses += 1
        else:
            self.cache_misses += 1
        return None

    def set_cached(self, key, value):
        self.cache[key] = (value, time.time())
        current_time = time.time()
        if current_time - self.last_cache_clear > 2.0:
            self.clear_expired_cache()
            self.last_cache_clear = current_time

    def clear_expired_cache(self):
        current_time = time.time()
        expired_keys = []
        for key, (value, timestamp) in self.cache.items():
            if current_time - timestamp > self.cache_timeout:
                expired_keys.append(key)
        for key in expired_keys:
            del self.cache[key]

    def find_roblox_process(self):
        hwnd, pid = self.find_window_by_exe("RobloxPlayerBeta.exe")
        if pid:
            self.hwnd = hwnd
            self.process_id = pid
        else:
            pid = self.get_process_id_by_psutil("RobloxPlayerBeta.exe")
            if not pid:
                return False
            self.process_id = pid
            hwnd, _ = self.find_window_by_exe("RobloxPlayerBeta.exe")
            self.hwnd = hwnd if hwnd else None
        self.process_handle = self.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, self.process_id)
        if not self.process_handle:
            return False
        self.base_address = self.get_module_address("RobloxPlayerBeta.exe")
        if not self.base_address:
            self.kernel32.CloseHandle(self.process_handle)
            return False
        return True

    def find_window_by_exe(self, exe_name):
        matches = []
        def enum_proc(hwnd, _):
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                try:
                    p = psutil.Process(pid)
                    pname = (p.name() or "").lower()
                    target = exe_name.lower()
                    target_noexe = target[:-4] if target.endswith(".exe") else target
                    if pname == target or pname == target_noexe:
                        matches.append((hwnd, pid))
                except Exception:
                    pass
                return True
            except Exception:
                return True
        try:
            win32gui.EnumWindows(enum_proc, None)
        except Exception:
            pass
        if matches:
            for hwnd, pid in matches:
                title = win32gui.GetWindowText(hwnd)
                if title:
                    return hwnd, pid
            return matches[0]
        return None, None

    def get_process_id_by_psutil(self, process_name):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() == process_name.lower():
                        return proc.info['pid']
                except Exception:
                    continue
            return None
        except Exception:
            return None

    def get_module_address(self, module_name):
        if not self.process_handle:
            return None
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x8 | 0x10, self.process_id)
        if snapshot == -1:
            return None
        module_entry = MODULEENTRY32()
        module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        if self.kernel32.Module32First(snapshot, ctypes.byref(module_entry)):
            while True:
                try:
                    name = module_entry.szModule.decode().lower()
                except Exception:
                    name = ""
                if module_name.lower() == name:
                    self.kernel32.CloseHandle(snapshot)
                    return ctypes.addressof(module_entry.modBaseAddr.contents)
                if not self.kernel32.Module32Next(snapshot, ctypes.byref(module_entry)):
                    break
        self.kernel32.CloseHandle(snapshot)
        return None

    def read_memory(self, address, size):
        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        result = self.kernel32.ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read))
        if result and bytes_read.value > 0:
            return buffer.raw[:bytes_read.value]
        return None

    def read_ptr(self, address):
        data = self.read_memory(address, 8)
        if data:
            return int.from_bytes(data, byteorder='little')
        return None

    def read_int(self, address):
        data = self.read_memory(address, 4)
        if data:
            return int.from_bytes(data, byteorder='little', signed=True)
        return None

    def read_int64(self, address):
        data = self.read_memory(address, 8)
        if data:
            return struct.unpack('q', data)[0]
        return None

    def read_float(self, address):
        data = self.read_memory(address, 4)
        if data:
            return struct.unpack('f', data)[0]
        return None

    def read_string(self, address):
        if not address:
            return ""
        str_length = self.read_int(address + 0x18)
        if not str_length or str_length <= 0 or str_length > 1000:
            return ""
        if str_length >= 16:
            address = self.read_ptr(address)
            if not address:
                return ""
        result = ""
        offset = 0
        while offset < str_length:
            char_data = self.read_memory(address + offset, 1)
            if not char_data:
                break
            char_val = char_data[0]
            if char_val == 0:
                break
            result += chr(char_val)
            offset += 1
        return result

    def initialize_game_data(self):
        try:
            self.fake_data_model = self.read_ptr(self.base_address + int(OFFSETS["FakeDataModelPointer"], 16))
            if not self.fake_data_model or self.fake_data_model == 0xFFFFFFFF:
                self.fake_data_model = None
                return
            self.data_model_pointer = self.read_ptr(self.fake_data_model + int(OFFSETS["FakeDataModelToDataModel"], 16))
            if not self.data_model_pointer or self.data_model_pointer == 0xFFFFFFFF:
                self.data_model_pointer = None
                return
            retry_count = 0
            data_model_name = ""
            while retry_count < 30:
                name_ptr = self.read_ptr(self.data_model_pointer + int(OFFSETS["Name"], 16)) if self.data_model_pointer else None
                data_model_name = self.read_string(name_ptr) if name_ptr else ""
                if data_model_name == "Ugc":
                    break
                time.sleep(1)
                retry_count += 1
                self.fake_data_model = self.read_ptr(self.base_address + int(OFFSETS["FakeDataModelPointer"], 16))
                if self.fake_data_model:
                    self.data_model_pointer = self.read_ptr(self.fake_data_model + int(OFFSETS["FakeDataModelToDataModel"], 16))
            if data_model_name != "Ugc":
                return
            self.data_model = self.data_model_pointer
            self.visual_engine = self.read_ptr(self.base_address + int(OFFSETS["VisualEnginePointer"], 16))
            if not self.visual_engine or self.visual_engine == 0xFFFFFFFF:
                self.visual_engine = None
                return
            self.workspace = self.find_first_child_which_is_a(self.data_model, "Workspace") if self.data_model else None
            self.players = self.find_first_child_which_is_a(self.data_model, "Players") if self.data_model else None
            if self.workspace:
                self.camera = self.find_first_child_which_is_a(self.workspace, "Camera")
            else:
                self.camera = None
            if self.players:
                local_player_ptr = self.read_ptr(self.players + int(OFFSETS["LocalPlayer"], 16)) if self.players else None
                if local_player_ptr:
                    self.local_player = local_player_ptr
                else:
                    self.local_player = None
            else:
                self.local_player = None
        except Exception:
            pass

    def get_children(self, parent_address):
        cache_key = f"children_{parent_address}"
        cached = self.get_cached(cache_key)
        if cached is not None:
            return cached
        children = []
        if not parent_address:
            self.set_cached(cache_key, children)
            return children
        children_ptr = self.read_ptr(parent_address + int(OFFSETS["Children"], 16))
        if not children_ptr:
            self.set_cached(cache_key, children)
            return children
        children_end = self.read_ptr(children_ptr + int(OFFSETS["ChildrenEnd"], 16))
        current_child = self.read_ptr(children_ptr)
        while current_child < children_end:
            child_ptr = self.read_ptr(current_child)
            if child_ptr:
                children.append(child_ptr)
            current_child += 0x10
        self.set_cached(cache_key, children)
        return children

    def get_instance_name(self, address):
        if not address:
            return ""
        cache_key = f"name_{address}"
        cached = self.get_cached(cache_key, 0.1)
        if cached is not None:
            return cached
        name_ptr = self.read_ptr(address + int(OFFSETS["Name"], 16))
        name = self.read_string(name_ptr) if name_ptr else ""
        self.set_cached(cache_key, name)
        return name

    def get_instance_class(self, address):
        if not address:
            return ""
        cache_key = f"class_{address}"
        cached = self.get_cached(cache_key, 0.1)
        if cached is not None:
            return cached
        class_descriptor = self.read_ptr(address + int(OFFSETS["ClassDescriptor"], 16))
        if class_descriptor:
            class_name_ptr = self.read_ptr(class_descriptor + int(OFFSETS["ClassDescriptorToClassName"], 16))
            class_name = self.read_string(class_name_ptr) if class_name_ptr else ""
            self.set_cached(cache_key, class_name)
            return class_name
        return ""

    def find_first_child_which_is_a(self, parent_address, class_name):
        cache_key = f"find_child_{parent_address}_{class_name}"
        cached = self.get_cached(cache_key, 0.05)
        if cached is not None:
            return cached
        children = self.get_children(parent_address)
        for child in children:
            if self.get_instance_class(child) == class_name:
                self.set_cached(cache_key, child)
                return child
        self.set_cached(cache_key, None)
        return None

    def find_first_child_by_name(self, parent_address, name):
        cache_key = f"find_child_name_{parent_address}_{name}"
        cached = self.get_cached(cache_key, 0.05)
        if cached is not None:
            return cached
        children = self.get_children(parent_address)
        for child in children:
            if self.get_instance_name(child) == name:
                self.set_cached(cache_key, child)
                return child
        self.set_cached(cache_key, None)
        return None

    def read_matrix4(self, address):
        data = self.read_memory(address, 64)
        if data:
            matrix = []
            for i in range(16):
                matrix.append(struct.unpack('f', data[i*4:(i+1)*4])[0])
            return matrix
        return None

    def get_team(self, player_ptr):
        if not player_ptr:
            return None
        team_ptr = self.read_ptr(player_ptr + int(OFFSETS.get("Team", "0x0"), 16))
        if not team_ptr:
            return None
        return team_ptr

    def get_player_coordinates(self):
        if not self.players or not self.local_player:
            return []
        coordinates = []
        player_instances = self.get_children(self.players)
        for player_ptr in player_instances:
            if not player_ptr:
                continue
            if player_ptr == self.local_player:
                continue
            player_name = self.get_instance_name(player_ptr)
            if not player_name:
                continue
            character_ptr = self.read_ptr(player_ptr + int(OFFSETS["ModelInstance"], 16))
            if not character_ptr:
                continue
            if self.get_instance_class(character_ptr) != "Model":
                continue
            humanoid_root_part = self.find_first_child_by_name(character_ptr, "HumanoidRootPart")
            if not humanoid_root_part:
                continue
            if self.get_instance_class(humanoid_root_part) != "Part":
                continue
            primitive = self.read_ptr(humanoid_root_part + int(OFFSETS["Primitive"], 16))
            if not primitive:
                continue
            position_data = self.read_memory(primitive + int(OFFSETS["Position"], 16), 12)
            if not position_data:
                continue
            x, y, z = struct.unpack('fff', position_data)
            position = vec3(x, y, z)
            size_data = self.read_memory(primitive + int(OFFSETS["PartSize"], 16), 12)
            if size_data:
                sx, sy, sz = struct.unpack('fff', size_data)
                player_size = vec3(sx, sy, sz)
            else:
                player_size = vec3(2.0, 5.0, 1.0)
            head_part = self.find_first_child_by_name(character_ptr, "Head")
            head_pos = None
            if head_part:
                head_primitive = self.read_ptr(head_part + int(OFFSETS["Primitive"], 16))
                if head_primitive:
                    head_position_data = self.read_memory(head_primitive + int(OFFSETS["Position"], 16), 12)
                    if head_position_data:
                        hx, hy, hz = struct.unpack('fff', head_position_data)
                        head_pos = vec3(hx, hy, hz)
            if not head_pos:
                head_pos = vec3(position.x, position.y + player_size.y / 2 + 1.0, position.z)
            humanoid = self.find_first_child_which_is_a(character_ptr, "Humanoid")
            health = None
            max_health = None
            if humanoid:
                health_addr = humanoid + int(OFFSETS["Health"], 16)
                max_health_addr = humanoid + int(OFFSETS["MaxHealth"], 16)
                health = self.read_float(health_addr)
                max_health = self.read_float(max_health_addr)
            coordinates.append({
                "player_name": player_name,
                "root_pos": position,
                "head_pos": head_pos,
                "player_size": player_size,
                "player_ptr": player_ptr,
                "character_ptr": character_ptr,
                "humanoid_root_part_ptr": humanoid_root_part,
                "health": health,
                "max_health": max_health
            })
        return coordinates

    def get_window_viewport(self):
        if not self.hwnd:
            return vec2(1920, 1080)
        try:
            left, top, right, bottom = win32gui.GetClientRect(self.hwnd)
            width = float(right - left)
            height = float(bottom - top)
            if width <= 0 or height <= 0:
                rect = win32gui.GetWindowRect(self.hwnd)
                width = float(rect[2] - rect[0])
                height = float(rect[3] - rect[1])
            return vec2(width, height)
        except Exception:
            return vec2(1920, 1080)

    def world_to_screen(self, pos):
        if not self.visual_engine:
            return vec2(-1, -1)
        try:
            view_matrix = self.read_matrix4(self.visual_engine + int(OFFSETS["viewmatrix"], 16))
            if not view_matrix:
                return vec2(-1, -1)
            qx = (pos.x * view_matrix[0]) + (pos.y * view_matrix[1]) + (pos.z * view_matrix[2]) + view_matrix[3]
            qy = (pos.x * view_matrix[4]) + (pos.y * view_matrix[5]) + (pos.z * view_matrix[6]) + view_matrix[7]
            qz = (pos.x * view_matrix[8]) + (pos.y * view_matrix[9]) + (pos.z * view_matrix[10]) + view_matrix[11]
            qw = (pos.x * view_matrix[12]) + (pos.y * view_matrix[13]) + (pos.z * view_matrix[14]) + view_matrix[15]
            if qw < 0.1:
                return vec2(-1, -1)
            ndc_x = qx / qw
            ndc_y = qy / qw
            viewport = self.get_window_viewport()
            width = viewport.x
            height = viewport.y
            x = (width / 2.0) * (1.0 + ndc_x)
            y = (height / 2.0) * (1.0 - ndc_y)
            if x < 0 or x > width or y < 0 or y > height:
                return vec2(-1, -1)
            return vec2(x, y)
        except Exception:
            return vec2(-1, -1)

    def get_place_id(self):
        if not self.data_model:
            return None
        cache_key = "place_id"
        cached = self.get_cached(cache_key, 1.0)
        if cached is not None:
            return cached
        try:
            place_id = self.read_int64(self.data_model + int(OFFSETS["PlaceId"], 16))
            if place_id:
                self.set_cached(cache_key, place_id)
                return place_id
        except Exception:
            pass
        self.set_cached(cache_key, None)
        return None

    def print_game_info(self):
        player_coords = self.get_player_coordinates()
        print(f"found {len(player_coords)} player instances [humanoids]")
        for p in player_coords:
            root_pos = p["root_pos"]
            health_info = f"health: {p['health']:.1f}/{p['max_health']:.1f}" if p['health'] is not None and p['max_health'] is not None else "health: Unknown"
            print(f"got pos : {p['player_name']}: ({root_pos.x:.2f}, {root_pos.y:.2f}, {root_pos.z:.2f}) | {health_info}")


def main():
    try:
        external = robloxmemory()
        external.print_game_info()
    except Exception as e:
        print(f"err : {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()