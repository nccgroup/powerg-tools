# PowerG Analysis Tools

A collection of tools for reverse engineering and interacting with the PowerG radio protocol.

This release accompanies the research James Chambers and Sultan Qasim Khan presented at REcon and hardwear.io.
Please see the presentation recording and slides for more information:

* <https://hardwear.io/usa-2025/presentation/powerg_hardweario_2025.pdf>
* <https://www.youtube.com/watch?v=ptM3iuD0Qfw>


## Directory structure

* `gnuradio`: GNU Radio project for capturing and decoding PowerG radio packets.
* `pkt_scripts`: Python tools for parsing PowerG packet payloads.
* `ghidra_scripts`: Ghidra scripts to help with reverse engineering CC13x0 firmware.


## Open-Source License

```
PowerG Analysis Tools
Copyright (C) 2025  NCC Group

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
```
