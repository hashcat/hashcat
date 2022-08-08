The files in this folder are used to override autotune settings

You can override configuration settings for Vector-Width, Kernel-Accel and/or Kernel-Loops values
You can filter by Device-Name, Device-Name alias, Attack-Mode and/or Hash-Type

Each file in this folder with the filename suffix .hctune will be automatically loaded by hashcat on startup with random order

- A valid line consists of the following fields (in that order):
  - Device-Name
  - Attack-Mode
  - Hash-Type
  - Vector-Width
  - Kernel-Accel
  - Kernel-Loops
- The first three columns define the filter, the other three is what is assigned when that filter matches
- If no filter matches, autotune is used
- Columns are separated with one or many spaces or tabs
- A line can not start with a space or a tab
- Comment lines are allowed, use a # as first character
- Invalid lines are ignored
- The Device-Name is the OpenCL Device-Name. It's shown on hashcat startup.
  - If the device contains spaces, replace all spaces with _ character.
- The Device-Name can be assigned an alias. This is useful if many devices share the same chip
  - If you assign an alias, make sure to not use the devices name directly
- There's also a hard-wired Device-Name which matches all device types called:
  - DEVICE_TYPE_CPU
  - DEVICE_TYPE_GPU
  - DEVICE_TYPE_ACCELERATOR
- The use of wildcards is allowed, some rules:
  - Wildcards can only replace an entire Device-Name, not parts just of it. eg: not Geforce_*
  - The policy is local > global, means the closer you configure something, the more likely it is selected
  - The policy testing order is from left to right
- Attack modes can be:
  - 0 = Dictionary-Attack
  - 1 = Combinator-Attack, will also be used for attack-mode 6 and 7 since they share the same kernel
  - 3 = Mask-Attack
- The Kernel-Accel is a multiplier to OpenCL's concept of a workitem, not the workitem count
- The Kernel-Loops has a functionality depending on the hash-type:
  - Slow Hash: Number of iterations calculated per workitem
  - Fast Hash: Number of mutations calculated per workitem
- None of both should be confused with the OpenCL concept of a "thread", this one is maintained automatically
- The Vector-Width can have only the values 1, 2, 4, 8 or 'N', where 'N' stands for native, which is an OpenCl-queried data value
- The Kernel-Accel is limited to 1024
- The Kernel-Loops is limited to 1024
- The Kernel-Accel can have 'A', where 'A' stands for autotune
- The Kernel-Accel can have 'M', where 'M' stands for maximum possible
- The Kernel-Loops can have 'A', where 'A' stands for autotune
- The Kernel-Loops can have 'M', where 'M' stands for maximum possible
