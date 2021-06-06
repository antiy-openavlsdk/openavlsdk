# ANTIY-OPENAVLSDK
Antiy Open AVL SDK is based on AVLSDK and forms Open AVLSDK through a lightweight transformation, which provides efficient, fast and professional security protection capabilities interfaces for cooperative developers, and provides free solutions with anti-virus capabilities for security products or services.

## Features 
(1)Detection capability

	With a large number of virus detection rules, it supports the detection of 8 types of malicious code,such as Trojan, worms, infectious viruses, hacking tools, gray-ware, risk software, test software, junk files, and no less than 50,000 malicious code families.
	
(2)Detection speed

	Fast detection speed, return detection result quickly.
	
(3)Resource occupancy

	Realize comprehensive detection capabilities under the premise of occupying very few system resources.
(4)Cross-platform

	Support POSIX standard, can be applied to various system platforms (such as Windows, Linux, etc.) and hardware platforms (such as Intel, Arm, MIPS, etc.).
(5)Simple API interface

	The API interface is simple and easy to integrate.
	You only need to simply call the interface to make the product have anti-virus capabilities. 


## Adaptable platform

- windows_x86

- centos_x64

- We will continue to increase it in the future


## Documentation Manual

* [开放引擎接口规范手册_v1.0](doc/开放引擎接口规范手册_v1.0.docx)

* [Open_AVLSDK Interface Specification Manual_v1.0 .docx](doc/Open_AVLSDK%20Interface%20Specification%20Manual_v1.0%20.docx)


## Default path structure
* 	Module  - Detection module
*	License -  Engine authorization file
*	Data  - Library files required by the engine
*	interface  - The header file used to compile the demo


## Instructions  
1.If the customer only performs testing, he can directly select the corresponding platform version. Execute the AVLScanner command line example in the open_avlsdk directory ./AVLScanner | AVLVScanner.exe -c ./Config/opensdk.ct -f TestFile 
2.If you develop the SDK, you can refer to AVLSCanner/demo.c and the interface specification manual. 

	
## License
This project is released under the GPL license.	
	
## Disclaimer
Copyright (C) 2021 Antiy Company, <openavlsdk@antiy.cn>, et al
  Licensed under the GNU General Public License v3.0

  This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

  This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

  Some open source projects are used in this project, please read declaration_list.md for the original declaration.
  If there is any infringement, please send an email to <openavlsdk@antiy.cn> 


