# Volatility plugin: BitLocker

Volatility plugin that retrieves the Full Volume Encryption Key (FVEK) in memory. The FVEK can then be used with [Dislocker](https://github.com/Aorimn/dislocker) to decrypt the volume. 
This plugin has been tested on every 64-bit Windows version from Windows 7 to Windows 10 and is fully compatible with Dislocker.

This work was done during my internship at [Synetis](https://www.synetis.com/).

Available options:

- Dump-dir: Dump the key to use it with bdemount, need an output path
- Dislocker: Dump the key to use it with Dislocker, need an output path
- Verbose: Add more information about the memory pools currently reviewed
- Debug: When the correct FVEK is not returned, it might help

## Installation

Just copy the bitlocker.py file into the volatily plugin path: 

```
cp bitlocker.py path/to/volatility/volatility/plugins/ 
```

## Example

Dump a memory image (it can be done using FTK Imager for example), and type:

```
python vol.py -f ${DUMP.raw} bitlocker --profile=${Windows_Profile} 
```

This will print the potential found FVEKs. The first returned should be the one as the plugin goes from the current Windows versions to the oldest.


To test the FVEK with Dislocker, you can add the Dislocker option: 

```
python vol.py -f ${DUMP.raw} bitlocker --profile=${Windows_Profile} --dislocker /path/to/dump
```

The output will look like this:

```
Volatility Foundation Volatility Framework 2.6.1

[FVEK] Address : 0xb7811050c9a0
[FVEK] Cipher  : AES-XTS 128 bit (Win 10+)
[FVEK] FVEK: 3ba9a1c2dde7c63e5f7851914a9dd120
[DISL] FVEK for Dislocker dumped to file: path/to/dump/0xb7811050c9a0-Dislocker.fvek



[FVEK] Address : 0xb78110504cc0
[FVEK] Cipher  : AES 128-bit (Win 8+)
[FVEK] FVEK: 8002ed825cfe78a3148640365511c03b
[DISL] FVEK for Dislocker dumped to file: path/to/dump/0xb78110504cc0-Dislocker.fvek



[FVEK] Address : 0xb78110ad8580
[FVEK] Cipher  : AES 256-bit (Win 8+)
[FVEK] FVEK: 5f75f4782de42f3df2c33b3a89a5d15775730e47327d4a1160c0559f3fd752d0
[DISL] FVEK for Dislocker dumped to file: path/to/dump/0xb78110ad8580-Dislocker.fvek



[FVEK] Address : 0xb781133b4990
[FVEK] Cipher  : AES 128-bit (Win 8+)
[FVEK] FVEK: 922eff6970d6b214d81539297aea715f
[DISL] FVEK for Dislocker dumped to file: path/to/dump/0xb781133b4990-Dislocker.fvek
```

After that, you can mount the disk by using Dislocker:

```
dislocker -k path/to/dump/0xb7811050c9a0-Dislocker.fvek /path/to/disk /path/to/dislocker && mount /path/to/dislocker/dislocker-file /path/to/mount
```

## Issues with bdemount

While Dislocker will mount the volume in read-write mode, bdemount will respect the hibernation flag and may mount it in read-only mode. Moreover, there is one known issue which makes bdemount and my output not compatible for AES-XTS 128-bit key. 

I recommend to use Dislocker.

## Credits

Credits to Marcin Ulikowski (https://github.com/volatilityfoundation/community/tree/master/MarcinUlikowski) and TribalChicken (https://github.com/tribalchicken/volatility-bitlocker and https://tribalchicken.net/recovering-bitlocker-keys-on-windows-8-1-and-10) for previous works.
