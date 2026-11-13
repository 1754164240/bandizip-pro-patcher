# -*- coding: utf-8 -*-
"""Bandizip 7.47 (build 71912) 离线注册补丁 —— 可重复使用脚本

用法：
    python apply_patch.py            应用补丁
    python apply_patch.py --restore  还原官方原版（从 Bandizip.exe.bak）

原理（静态逆向 + Frida 运行时验证）：
  程序在 RVA 0x1316C0 有一个 edition 映射函数，它从全局 app 对象读取
      app+0x60 : L"ok"           表示 license 有效
      app+0x28 : L"PRO"/L"ENT"   表示版本
  并把结果位混淆后写入 app 单例(0x131030 返回对象)的 +0x120：
      PRO -> 0x3D4  -> 解码 1000  -> "Professional"
      ENT -> 0x1B20 -> 解码 10000 -> "Enterprise"
      其它 -> 0x98  -> 解码 100   -> "Standard"
  窗口标题、广告开关、Pro 功能开关都读这个数值。

  本补丁把 0x1316C0 函数开头替换为：
      - 取 app 单例（RVA 0xCF570）
      - 用程序自身的 std::wstring assign（RVA 0x18F50）写入
            app+0x60 = L"ok"，app+0x28 = L"PRO"
      - this+0x120 = 0x3D4  (Professional)
      - ret
  共 78 字节，函数原始长度 0x157，未新增节、文件大小不变。

校验：
    原始 SHA256 = 2D733A26500A8CFF7DB04291C396B3D48E9D7275753E2A06BF3564C9F9591DC8
    补丁 SHA256 = E0D8170B17822AB611E87E7C021B83E22EAE6564C75B9E2BF8CFCCDB4B53D6AA
"""
import hashlib
import os
import shutil
import struct
import sys

PATH = r'D:\Program Files\Bandizip\Bandizip.exe'
BAK = PATH + '.bak'

ORIG_SHA = '2d733a26500a8cff7db04291c396b3d48e9d7275753e2a06bf3564c9f9591dc8'
TEXT_RAW = 0x400      # .text PointerToRawData
TEXT_RVA = 0x1000     # .text VirtualAddress

FUNC = 0x1316C0       # edition mapper
GETAPP = 0xCF570      # app singleton getter
ASSIGN = 0x18F50      # std::wstring::assign(this, const wchar_t*, size_t)
S_OK = 0x2A6B40       # L"ok"
S_PRO = 0x2A6B38      # L"PRO"


def off(rva):
    return TEXT_RAW + (rva - TEXT_RVA)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build_code():
    c = bytearray()
    c += b'\x53'                                    # push rbx
    c += b'\x48\x83\xec\x20'                        # sub rsp,0x20  (shadow space)
    c += b'\x48\x89\xcb'                            # mov rbx,rcx   (this)
    p1 = len(c)
    c += b'\xe8' + b'\0' * 4                        # call getApp
    c += b'\x48\x8d\x48\x60'                        # lea rcx,[rax+0x60]
    l1 = len(c)
    c += b'\x48\x8d\x15' + b'\0' * 4                # lea rdx,[rip+S_OK]
    c += b'\x41\xb8\x02\x00\x00\x00'                # mov r8d,2
    k1 = len(c)
    c += b'\xe8' + b'\0' * 4                        # call assign
    p2 = len(c)
    c += b'\xe8' + b'\0' * 4                        # call getApp
    c += b'\x48\x8d\x48\x28'                        # lea rcx,[rax+0x28]
    l2 = len(c)
    c += b'\x48\x8d\x15' + b'\0' * 4                # lea rdx,[rip+S_PRO]
    c += b'\x41\xb8\x03\x00\x00\x00'                # mov r8d,3
    k2 = len(c)
    c += b'\xe8' + b'\0' * 4                        # call assign
    c += bytes.fromhex('c78320010000d4030000')      # mov dword [rbx+0x120],0x3D4
    c += b'\x48\x83\xc4\x20'                        # add rsp,0x20
    c += b'\x5b'                                    # pop rbx
    c += b'\xc3'                                    # ret

    def place(field, start, ln, target):
        struct.pack_into('<i', c, field, target - (FUNC + start + ln))

    place(p1 + 1, p1, 5, GETAPP)
    place(l1 + 3, l1, 7, S_OK)
    place(k1 + 1, k1, 5, ASSIGN)
    place(p2 + 1, p2, 5, GETAPP)
    place(l2 + 3, l2, 7, S_PRO)
    place(k2 + 1, k2, 5, ASSIGN)
    return bytes(c)


def apply():
    if not os.path.exists(BAK):
        shutil.copy2(PATH, BAK)
        print('已创建备份: %s' % BAK)
    d = bytearray(open(PATH, 'rb').read())
    cur = sha(bytes(d))
    if cur != ORIG_SHA:
        print('当前文件不是原始版本 (sha256=%s)，先从未修改备份还原' % cur)
        shutil.copy2(BAK, PATH)
        d = bytearray(open(PATH, 'rb').read())
    code = build_code()
    assert len(code) < 0x157
    d[off(FUNC):off(FUNC) + len(code)] = code
    open(PATH, 'wb').write(bytes(d))
    print('已打补丁，%d 字节，sha256=%s' % (len(code), sha(bytes(d))))
    print('启动 Bandizip，标题应显示 "Bandizip (Professional)"')


def restore():
    if not os.path.exists(BAK):
        print('没有备份文件 %s' % BAK)
        return
    shutil.copy2(BAK, PATH)
    print('已还原官方原版，sha256=%s' % sha(open(PATH, 'rb').read()))


if __name__ == '__main__':
    if '--restore' in sys.argv:
        restore()
    else:
        apply()
