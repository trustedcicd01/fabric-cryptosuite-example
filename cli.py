#!/usr/bin/env python3

import argparse, sys, logging, re, json, urllib.parse
from subprocess import check_output, STDOUT

logger = logging.getLogger('sample')
verbose = 0
host = ''

def call_api(api, cmd):
    if verbose > 0:
        logger.info(api + ': cmd=' + cmd)
    try:
        resp_str = check_output(cmd, shell=True).rstrip().decode('utf8')
    except:
        logger.fatal(api + ' failed: ' + sys.exc_info()[0])
        sys.exit(-1)
    try:
        resp = json.loads(resp_str)
        logger.info(api + ': response=' + json.dumps(resp, indent=4))
        return resp
    except:
        if resp_str == '':
            logger.info(api + ': response=None')
        else:
            logger.info(api + ': response=' + resp_str + '[exception]')
    return resp_str

def setup():
    cmd = 'curl -s -X POST http://' + host + '/setup'
    return call_api('setup', cmd)

def register(user):
    cmd = 'curl -s -X POST http://' + host + '/users'
    cmd = cmd + ' -H "content-type: application/json" -d \'{"username":"' + user + '"}\''
    return call_api('register', cmd)

def enroll(user, secret):
    cmd = 'curl -s -X PUT http://' + host + '/users'
    cmd = cmd + ' -H "content-type: application/json" -d \'{"username":"' + user + '","secret":"' + secret + '"}\''
    return call_api('enroll', cmd)

def invoke(channelName, chaincodeName, user, fcn, key, value):
    cmd = 'curl -s -X POST http://' + host + '/channels/' + channelName + '/chaincodes/' + chaincodeName
    body = {}
    body['fcn'] = fcn
    body['args'] = [key, value]
    body['username'] = user
    cmd = cmd + ' -H "content-type: application/json" -d \'' + json.dumps(body) + '\''
    return call_api('invoke', cmd)

def query(channelName, chaincodeName, user, fcn, key):
    cmd = 'curl -s -X GET http://' + host + '/channels/' + channelName + '/chaincodes/' + chaincodeName
    query = {}
    query['fcn'] = fcn
    query['args'] = [key]
    query['username'] = user
    cmd = cmd + '?' + urllib.parse.urlencode(query).replace('&', '\&')
    resp = call_api('invoke', cmd)
    if 'status' in resp and resp['status'] == 200 and 'payload' in resp and 'data' in resp['payload']:
        data = resp['payload']['data']
        value = ''.join(chr(i) for i in data)
        logger.info('value=' + value)

if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    
    parser = argparse.ArgumentParser(prog='cli.py')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='increase verbosity')
    parser.add_argument('command', help='[setup|register|enroll|invoke|query]')
    parser.add_argument('--host', default='localhost', help='fabric client')
    parser.add_argument('--port', default='8080', help='fabric client')
    parser.add_argument('--user', default='user1', help='username')
    parser.add_argument('--channel', default='mychannel', help='channel name')
    parser.add_argument('--chaincode', default='example', help='chaincode name')
    parser.add_argument('--secret', help='secret')
    parser.add_argument('--key', help='key')
    parser.add_argument('--value', help='value')
    parser.add_argument('--fcn', help='function')

    args = parser.parse_args()

    if args.verbose > 1:
        for name in vars(args).keys():
            if vars(args)[name]:
                print(name + " " + str(vars(args)[name]))

    verbose = args.verbose
    host = args.host + ':' + args.port
                
    if args.command == 'setup':
        setup()
    elif args.command == 'register':
        register(args.user)
    elif args.command == 'enroll':
        enroll(args.user, args.secret)
    elif args.command == 'invoke':
        if args.fcn == None:
            args.fcn = 'put'
        invoke(args.channel, args.chaincode, args.user, args.fcn, args.key, args.value)
    elif args.command == 'query':
        if args.fcn == None:
            args.fcn = 'get'
        query(args.channel, args.chaincode, args.user, args.fcn, args.key)
    else:
        logger.fatal('unknown command: ' + args.command)

