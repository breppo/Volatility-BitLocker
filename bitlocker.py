import volatility.plugins.common as common
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import volatility.poolscan as poolscan
import binascii
import os


class KeyPoolScan(poolscan.SinglePoolScanner):
    """ Pool scanner """


class Bitlocker(common.AbstractWindowsCommand):
    """Extract Bitlocker FVEK. Supports Windows 7 - 10."""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('DUMP-DIR', default=None, help='Directory in which to dump FVEK (can be used for bdemount)')
        config.add_option('DISLOCKER', default=None, help='Directory in which to dump FVEK for Dislocker')
        config.add_option('VERBOSE', default=None, help='Add more information')
        config.add_option('DEBUG', default=None, help='Here to Debug offset')

    def calculate(self):
        PoolSize = {
            'Fvec128': 508,
            'Fvec256': 1008,
            'Cngb128': 632,
            'Cngb256': 672,
            'None128': 1230,
            'None256': 1450,
        }
        BLMode = {
            '00': 'AES 128-bit with Diffuser',
            '01': 'AES 256-bit with Diffuser',
            '02': 'AES 128-bit',
            '03': 'AES 256-bit',
            '10': 'AES 128-bit (Win 8+)',
            '20': 'AES 256-bit (Win 8+)',
            '30': 'AES-XTS 128 bit (Win 10+)',
            '40': 'AES-XTS 256 bit (Win 10+)',
        }

        address_space = utils.load_as(self._config)
        winver = (address_space.profile.metadata.get("major", 0), address_space.profile.metadata.get("minor", 0),
                  address_space.profile.metadata.get("build"))
        arch = address_space.profile.metadata.get("memory_model", 0)

        if winver >= (6, 4, 10241):
            mode = "30"
            if self._config.VERBOSE:
                print(
                    "\n[INFO] Looking for some FVEKs inside memory pools used by BitLocker in Windows 10/2016/2019.\n")
            tweak = "Not Applicable"
            poolsize = lambda x: x >= PoolSize['None128'] and x <= PoolSize['None256']
            scanner = KeyPoolScan()
            scanner.checks = [
                ('PoolTagCheck', dict(tag="None")),
                ('CheckPoolSize', dict(condition=poolsize)),
                ('CheckPoolType', dict(paged=False, non_paged=True)),
            ]
            if (arch == '64bit'):
                fvek1OffsetRel = 0x9c
                fvek2OffsetRel = 0xe0
                fvek3OffsetRel = 0xc0  # Just for W2016 and W2019 using AES-CBC encryption method
            for offset in scanner.scan(address_space):
                pool = obj.Object("_POOL_HEADER", offset=offset, vm=address_space)
                f1 = address_space.zread(offset + fvek1OffsetRel, 64)
                f2 = address_space.zread(offset + fvek2OffsetRel, 64)
                f3 = address_space.zread(offset + fvek3OffsetRel, 64)
                if f1[0:16] == f2[0:16]:
                    if f1[16:32] == f2[16:32]:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("04") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['40'], tweak, f1[0:32], [fbis]
                        else:
                            yield pool, BLMode['40'], tweak, f1[0:32], []
                    else:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("05") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['30'], tweak, f1[0:16], [fbis]
                        else:
                            yield pool, BLMode['30'], tweak, f1[0:16], []
                if f1[0:16] == f3[0:16]:  # Should be AES-CBC
                    if f1[16:32] == f3[16:32]:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("03") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['20'], tweak, f1[0:32], [fbis]
                        else:
                            yield pool, BLMode['20'], tweak, f1[0:32], []
                    else:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("02") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['10'], tweak, f1[0:16], [fbis]
                        else:
                            yield pool, BLMode['10'], tweak, f1[0:16], []
                if self._config.DEBUG:
                    fvek = []
                    print("---------- START ----------")
                    for o, h, c in utils.Hexdump(f1):
                        fvek.append(h)
                    print(fvek)
                    fvek = []
                    for o, h, c in utils.Hexdump(f2):
                        fvek.append(h)
                    print(fvek)
                    fvek = []
                    for o, h, c in utils.Hexdump(f3):
                        fvek.append(h)
                    print(fvek)

        if winver >= (6, 2):
            if self._config.VERBOSE:
                print(
                    "\n[INFO] Looking for some FVEKs inside memory pools used by BitLocker in Windows 8/8.1/2012/older 10 versions.\n")
            tweak = "Not Applicable"
            poolsize = lambda x: x >= PoolSize['Cngb128'] and x <= PoolSize['Cngb256']
            scanner = KeyPoolScan()
            scanner.checks = [
                ('PoolTagCheck', dict(tag="Cngb")),
                ('CheckPoolSize', dict(condition=poolsize)),
                ('CheckPoolType', dict(paged=False, non_paged=True)),
            ]

            if (arch == '32bit'):
                modeOffsetRel = 0x5C
                fvek1OffsetRel = 0x4C
                fvek2OffsetRel = 0x9C

            if (arch == '64bit'):
                modeOffsetRel = 0x68
                fvek1OffsetRel = 0x6C
                fvek2OffsetRel = 0x90

            for offset in scanner.scan(address_space):
                pool = obj.Object("_POOL_HEADER", offset=offset, vm=address_space)
                f1 = address_space.zread(offset + fvek1OffsetRel, 64)
                f2 = address_space.zread(offset + fvek2OffsetRel, 64)
                if f1[0:16] == f2[0:16]:
                    if f1[16:32] == f2[16:32]:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("03") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['20'], tweak, f1[0:32], [fbis]
                        else:
                            yield pool, BLMode['20'], tweak, f1[0:32], []
                    else:
                        if self._config.DISLOCKER:
                            fbis = binascii.unhexlify("02") + binascii.unhexlify("80") + f1
                            yield pool, BLMode['10'], tweak, f1[0:16], [fbis]
                        else:
                            yield pool, BLMode['10'], tweak, f1[0:16], []
        if winver >= (6, 0):

            POOLSIZE_X86_AESDIFF = 976
            POOLSIZE_X86_AESONLY = 504
            POOLSIZE_X64_AESDIFF = 1008
            POOLSIZE_X64_AESONLY = 528

            OFFSET_DB = {
                POOLSIZE_X86_AESDIFF: {
                    'CID': 24,
                    'FVEK1': 32,
                    'FVEK2': 504
                },
                POOLSIZE_X86_AESONLY: {
                    'CID': 24,
                    'FVEK1': 32,
                    'FVEK2': 336
                },
                POOLSIZE_X64_AESDIFF: {
                    'CID': 44,
                    'FVEK1': 48,
                    'FVEK2': 528
                },
                POOLSIZE_X64_AESONLY: {
                    'CID': 44,
                    'FVEK1': 48,
                    'FVEK2': 480
                },
            }

            addr_space = utils.load_as(self._config)

            scanner = poolscan.SinglePoolScanner()
            scanner.checks = [
                ('PoolTagCheck', dict(tag='FVEc')),
                ('CheckPoolSize', dict(condition=lambda x: x in list(OFFSET_DB.keys()))),
            ]

            for addr in scanner.scan(addr_space):
                pool = obj.Object('_POOL_HEADER', offset=addr, vm=addr_space)

                pool_alignment = obj.VolMagic(pool.obj_vm).PoolAlignment.v()
                pool_size = int(pool.BlockSize * pool_alignment)

                cid = addr_space.zread(addr + OFFSET_DB[pool_size]['CID'], 2)
                fvek1 = addr_space.zread(addr + OFFSET_DB[pool_size]['FVEK1'], 32)
                fvek2 = addr_space.zread(addr + OFFSET_DB[pool_size]['FVEK2'], 32)

                if ord(cid[1]) == 0x80 and ord(cid[0]) <= 0x03:
                    if ord(cid[0])==0x02 or ord(cid[0])==0x00:
                        length = 16
                    else:
                        length=32
                    fvek = fvek1 + fvek2
                    mode = '{:02x}'.format(ord(cid[0]))
                    yield pool, BLMode[mode], fvek2[0:length] if mode!="02" and mode!="03" else "Not Applicable", fvek1[0:length], [binascii.unhexlify(mode) + binascii.unhexlify("80") + fvek]

    def unified_output(self, data):
        return TreeGrid([("Address", Address),
                         ("Cipher", str),
                         ("FVEK", str),
                         ("TWEAK Key", str),
                         ], self.generator(data))

    def generator(self, data):
        for (pool, BLMode, tweak, fvek_raw, fbis) in data:
            fvek = []
            for o, h, c in utils.Hexdump(fvek_raw):
                fvek.append(h)
            yield (
                0, [Address(pool), BLMode, str(''.join(fvek).replace(" ", "")), str(''.join(tweak).replace(" ", "")), ])

    def render_text(self, outfd, data):
        for (pool, BLMode, tweak_raw, fvek_raw, fbis) in data:
            fvek = []
            for o, h, c in utils.Hexdump(fvek_raw):
                fvek.append(h)
            if tweak_raw != "Not Applicable":
                tweak = []
                for o, h, c in utils.Hexdump(tweak_raw):
                    tweak.append(h)
            else:
                tweak = tweak_raw
            if tweak != "Not Applicable":
                outfd.write("\n" +
                            "[FVEK] Address : " + '{0:#010x}'.format(pool.obj_offset) + "\n" +
                            "[FVEK] Cipher  : " + BLMode + "\n" +
                            "[FVEK] FVEK    : " + ''.join(fvek).replace(" ", "") + "\n" +
                            "[FVEK] Tweak   : " + ''.join(tweak).replace(" ", "") + "\n")
            else:
                outfd.write("\n" +
                            "[FVEK] Address : " + '{0:#010x}'.format(pool.obj_offset) + "\n" +
                            "[FVEK] Cipher  : " + BLMode + "\n" +
                            "[FVEK] FVEK: " + ''.join(fvek).replace(" ", "") + "\n")
            if self._config.DUMP_DIR:
                full_path = os.path.join(self._config.DUMP_DIR, '{0:#010x}.fvek'.format(pool.obj_offset))
                with open(full_path, "wb") as fvek_file:
                    if tweak == "Not Applicable":
                        fvek_file.write(''.join(fvek).replace(" ", "") + "\n")
                    else:
                        fvek_file.write(''.join(fvek).replace(" ", "") + ":" + ''.join(tweak).replace(" ", "") +"\n")
                outfd.write('[DUMP] FVEK dumped to file: {}\n'.format(full_path))
            if self._config.DISLOCKER:
                full_path_dislocker = os.path.join(self._config.DISLOCKER,
                                                   '{0:#010x}-Dislocker.fvek'.format(pool.obj_offset))
                with open(full_path_dislocker, "wb") as fvek_file_dis:
                    if fbis != []:
                        fvek_file_dis.write(fbis[0])
                        outfd.write('[DISL] FVEK for Dislocker dumped to file: {}\n'.format(full_path_dislocker))
            if self._config.DISLOCKER or self._config.DUMP_DIR:
                print('\n')
