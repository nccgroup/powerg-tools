# PowerG Packet Capture

Open `grc/fhss_detector_powerg.grc` with GNU Radio Companion to begin capturing PowerG packets.

By default, the project is configured to capture the 915 MHz variant of PowerG with a [HackRF One](https://greatscottgadgets.com/hackrf/one/) source.
Decoded packet data is saved to a file named `powerg_burst_bytes_<timestamp>.csv` in the same directory as the GRC file.
An example capture file can be found at `pkt_scripts/data/powerg_burst_bytes_2025-06-06T13:34:44.353027.csv`.

The capture device setup can be configured with the "osmocom Source" block at the beginning of the flow.
Any SDR that can capture the full bandwidth of PowerG should be suitable for performing captures, but we have only tested this setup with a HackRF One.
For the 915 MHz variant used in North America, the full bandwidth is about 6.5 MHz.

The output file path can be changed in the `csv_output_file` variable block at the bottom-right of the flow.


## GNU Radio Setup

Tested with:

* Ubuntu 22, GNU Radio 3.10.7.0, gr-osmosdr 0.2.4
* Ubuntu 24, GNU Radio 3.10.9.2, gr-osmosdr 0.2.6


Make sure to remove everything related to GNU Radio from the system first.

1. Install GNU Radio version 3.10.7.0 or higher: <https://wiki.gnuradio.org/index.php/InstallingGR>
2. Install gr-osmosdr: <https://osmocom.org/projects/gr-osmosdr/wiki>
3. Build and install these Sandia libraries from sources (branch `maint-3.10` for all repos):
   * https://github.com/sandialabs/gr-pdu_utils
   * https://github.com/sandialabs/gr-sandia_utils
   * https://github.com/sandialabs/gr-timing_utils
   * https://github.com/sandialabs/gr-fhss_utils


### Building Sandia GR libraries

General flow for building and installing these libraries:

1. `cd` into project directory
2. `mkdir build; cd build; cmake ..`
3. `make`
4. `sudo make install`


#### Ubuntu 24 patches

You may need to apply these patches to build all libraries on Ubuntu 24.

For `gr-pdu_utils`:

```diff
diff --git a/lib/pdu_align_impl.cc b/lib/pdu_align_impl.cc
index 34a8a9b..d295a6e 100644
--- a/lib/pdu_align_impl.cc
+++ b/lib/pdu_align_impl.cc
@@ -15,6 +15,7 @@
 #include <gnuradio/io_signature.h>
 #include <gnuradio/pdu_utils/constants.h>
 #include <volk/volk.h>
+#include <bitset>

 namespace gr {
 namespace pdu_utils {
```

For `gr-sandia_utils`:

```diff
diff --git a/lib/epoch_time.h b/lib/epoch_time.h
index e6d2bfc..5fc6c77 100644
--- a/lib/epoch_time.h
+++ b/lib/epoch_time.h
@@ -13,6 +13,7 @@
 #include <sys/time.h> /* struct timeval, gettimeofday */
 #include <cmath>      /* modf */
 #include <iostream>
+#include <cstdint>

 namespace gr {
 namespace sandia_utils {
```


## PowerG Regional Variants

These capture scripts have only been tested on the 915 MHz variant of PowerG hardware.
Information on the other variants is based on reverse engineering the regional firmware versions, but it may be incomplete or incorrect.


> 915 MHZ = NORTH AMERICA, LATAM, CARIBBEAN  
> 433 MHZ = AFRICA, ASIA, AUSTRALIA, EASTERN EUROPE, BRAZIL, PERU, URUGUAY, NEW ZEALAND  
> 868 MHZ = AFRICA, EASTERN EUROPE, WESTERN EUROPE, UK, MIDDLE EAST  


### 915 MHz

* Base: 915,000,000 Hz
* Spacing: 129,730 Hz
* Num. channels: 50


### 868 MHz

* Base: 868,000,000 Hz
* Spacing: 50,087 Hz
* Num. channels: 4 active (zero-based channel IDs: 4, 8, 17, 21)


### 433 MHz

* Base: 433,000,000 Hz
* Spacing: 200,384 Hz
* Num. channels: 8
