# HP updates

This page documents published HP updates related to fixing issues with Credential Guard, Device Guard, and Virtualization-based protection of code integrity (aka HVCI). You can: 

* **[View the CSV file on GitHub](./Updates.csv) which is easier to read than the table below and is searchable.** 
* Download the CSV file by clicking the **Raw** button available at the previous link, save the file to your local system, and then open the file in Excel. 

System device driver updates resolve compatibility issues with Virtualization-based protection of code integrity. 

System BIOS/firmware updates resolve compatibility issues with Device Guard when assigning a Device Guard code integrity policy would cause the system to lock up on boot and also prevent system shutdown unless a hard reset was performed.

These updates were discovered via a search for ["Device Guard feature" site:www2.hp.com](https://encrypted.google.com/search?oq="Device+Guard+feature"+site%3Awww2.hp.com&ie=UTF-8&q="Device+Guard+feature"+site%3Awww2.hp.com)

| Description | Version | Date | Applies to | Link | Notes |
| --- | --- | --- | --- | --- | --- |
| Broadcom Ethernet Contoller Drivers | 17.2.0.2 Rev.A | 11 January 2016 | HP EliteBook 745 G3 Notebook PC, HP EliteBook 755 G3 Notebook PC, HP ZBook 17 G3 Mobile Workstation, HP EliteBook 725 G3 Notebook PC, HP ZBook 15 G3 Mobile Workstation, HP EliteBook Folio G1 Notebook PC | [Download](http://h20564.www2.hp.com/hpsc/swd/public/detail?swItemId=ob_160891_1) | Provides support for the Device Guard feature |
| Broadcom NIC Drivers for Microsoft Win7/8/8.1/10 -64bit | 17.2.0.2 Rev.A | 1 February 2016 | HP EliteOne 705 G2 23-in Touch All-in-One PC, HP EliteDesk 705 G2 DM Business PC, HP EliteDesk 705 G2 MT Business PC, HP EliteDesk 705 G2 SFF Business PC | [Download](http://h20564.www2.hp.com/hpsc/swd/public/detail?swItemId=vc_164351_1) | Adds support for Device Guard feature |
| HP EliteDesk 705 G2 System BIOS (N06) | 00.02.16 Rev.A | 20 Jun 2016 | HP EliteDesk 705 G2 MT Business PC, HP EliteDesk 705 G2 SFF Business PC | [Download](http://h20564.www2.hp.com/hpsc/swd/public/detail?swItemId=vc_168302_1) | Fixes Device Guard issue where resuming from Sleep mode could cause the system to fail and display a black screen |