# [Twinkly](https://twinkly.com) Tree Helper
## AI Disclaimer
This code and some doc were written by ChatGPT 5.2 from my specific direction.
I’ve tested and reviewed the functionality, but have reviewed the code very
little.

## Objective
A small Linux-friendly CLI to help you _physically_ locate LEDs (especially the
end of each physical string) by lighting specific lamps or running simple chase
patterns, using Twinkly’s local LAN API.

My initial motivation was being able to carefully remove Twinkly lights from a
large tree (four 300-lamp strings) without tangles.

## Usage
Please see the built-in help, and comments in the source code, to learn how to
invoke the program. Initialize with:

```bash
./twinkly_tree_helper.py discover --write-params
```
You may need to specify `--segment-len`, or edit the parameter file
afterwards, if your controllers don’t each have two strings of 300 lights.

My simplest and most useful command has been:

```bash
./twinkly_tree_helper.py light --string <name> --rgb #00ff00 --rgb2 #ff0000
```
Where `<name>` is a name derived during _discover_. This will light a color
gradient of lights, with the controller end green and the tail end red. This
makes it easy to find the end to start removal.

Before running this, use the Twinkly phone app to set lights to a fixed color
black, or other color you want for lights not in the target string. Also, if
you have controllers in a group, be sure to either ungroup, or unplug
controllers that you aren’t targeting, otherwise you may find the pattern will
revert soon after you set it.

When you are done, hit Control-C to exit the utility.
