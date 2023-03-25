# Overview

`overlay-prototyping` is a Python Library and Framework meant to be a companion
to `IPython`.  This project borrows the memory overlay system used by 
[java8-memory-analysis](https://github.com/deeso/java8-memory-analysis).  The system uses a 
basic list of fields found in structures.  Then the Python code aims to interpret and 
process these fields with `struct`.  The goal is to offer some light-lifts for structures
and objects that point to other interdependent structures.


# Requirements
There are three prerequisites to using this tool:
1. git and Python3 with `virtualenv` and `pip3` installed
2. A Memory dump that can be analyzed  
3. Output from `luau-sift` in [luau-analysis](https://github.com/trumetaverse/luau-analysis)

# setup
```
git clone https://github.com/trumetaverse/overlay-prototyping
cd overlay-prototyping
python3 -m virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 setup.py install
```

# usage
1. start ipython shell
2. 
