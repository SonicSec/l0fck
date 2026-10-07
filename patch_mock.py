import re

with open('src/main.c', 'r') as f:
    content = f.read()

# Add mock_cave
if 'static uint64_t mock_cave[4] = {0};' not in content:
    content = content.replace('static uint64_t s_test15_flag_written = 0;', 'static uint64_t mock_cave[4] = {0};\nstatic uint64_t s_test15_flag_written = 0;')

# Patch kread64
kread_patch = """
    if (addr == fake_proc + KOFF_PROC_P_FLAG) {
        *out = 0;
        return 0;
    }
    uint64_t entry_addr = KOFF_TRUST_CACHE_RT + rw->kslide;
    uint64_t cave_addr = entry_addr - 0x4000;
    if (addr >= cave_addr && addr < cave_addr + 32) {
        *out = mock_cave[(addr - cave_addr) / 8];
        return 0;
    }
    return -1;
"""
content = re.sub(r'    if \(addr == fake_proc \+ KOFF_PROC_P_FLAG\) \{\n        \*out = 0;\n        return 0;\n    \}\n    return -1;', kread_patch, content)

# Patch kwrite64
kwrite_patch = """
    uint64_t entry_addr = KOFF_TRUST_CACHE_RT + rw->kslide;
    uint64_t cave_addr = entry_addr - 0x4000;
    if (addr >= cave_addr && addr < cave_addr + 32) {
        mock_cave[(addr - cave_addr) / 8] = value;
        return 0;
    }
    if (addr == entry_addr) {
        return 0;
    }
    return -1;
"""
content = re.sub(r'    uint64_t entry_addr = KOFF_TRUST_CACHE_RT \+ rw->kslide;\n    if \(addr >= entry_addr && addr < entry_addr \+ 32\) \{\n        return 0;\n    \}\n    return -1;', kwrite_patch, content)

with open('src/main.c', 'w') as f:
    f.write(content)
