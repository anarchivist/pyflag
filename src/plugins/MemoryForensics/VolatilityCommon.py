import os,sys

## Find and insert the volatility modules
volatility_path = None
for d in os.listdir(os.path.dirname(__file__)):
    if d.startswith("Volatility-1.3"):
        ## Check that volatility is actually in there
        path = os.path.join(os.path.dirname(__file__),d)
        if os.access(os.path.join(path,"vtypes.py"),os.F_OK):
            volatility_path = path
            break

## We need to make sure that we get in before an older version
if volatility_path and volatility_path not in sys.path:
    sys.path.insert(0,volatility_path)
