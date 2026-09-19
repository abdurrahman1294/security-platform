#!/usr/bin/env python3
"""Launch the local Security Platform web application."""
import argparse
import uvicorn
from webapp.app import app

if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--host',default='127.0.0.1')
    p.add_argument('--port',type=int,default=8000)
    args=p.parse_args()
    uvicorn.run(app,host=args.host,port=args.port,log_level='info')
