# NSX IDPS Signature Downloader

This script allows you to download the IDPS signatures from NSX Manager using the NSX API.

## Requirements

- Python 3.x
- Required Python packages can be installed using `pip`:
pip install requests urllib3


## Usage

1. Update the user-configurable options in the script:
 - Set the `base_url` variable to the URL of your NSX Manager.
 - Set the `username` variable to your NSX admin username.
 - Set the `password` variable to your corresponding NSX admin password.
 - Optionally, set the `output_directory` variable to specify a custom output directory for the downloaded signature file. If not specified, it will default to the same directory as the script.
 - Choose the desired `output_format` as either "csv" or "json" for the downloaded file.

2. Run the script:

python download_nsx_idps_sig.py


The script will retrieve the latest IDPS signature version ID from NSX Manager and download the signatures in the specified output format.

3. The downloaded signature file will be saved in the specified output directory or the same directory as the script.

## Example of running the script on a Windows 10 machine:
```
C:\Users\tyler>python download_nsx_idps_sig.py
The identified signature version is: IDPSSignatures.1725.2023-06-13T10:41:07Z
8% complete
17% complete
25% complete
33% complete
42% complete
50% complete
58% complete
67% complete
75% complete
83% complete
92% complete
100% complete
Data saved to IDPSSignatures.1725.csv

C:\Users\tyler>
```
## Example of running the script on a Ubuntu 22 machine:
```
tyler@tyler-virtual-machine:~$ python3 download_nsx_idps_sig.py
The identified signature version is: IDPSSignatures.1725.2023-06-13T10:41:07Z
8% complete
17% complete
25% complete
33% complete
42% complete
50% complete
58% complete
67% complete
75% complete
83% complete
92% complete
100% complete
Data saved to IDPSSignatures.1725.csv
tyler@tyler-virtual-machine:~$
```
## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Thank You

Special thanks to Jake (https://github.com/jgormanit) for the assistance in creating this script.
