#!/usr/bin/env python
#Generate a 18GB file to fill up disk

with open("big_file", "w") as f:
  for i in range(1, 1024 * 18):
    f.write("B" * 1024 * 1024)
  f.flush()
  f.close()
