import codecs
import frida

import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="Grant/Revoke permission to target uid with frida")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-g', '--grant', action='store_true', help='grant permission to target uid')
    group.add_argument('-r', '--revoke', action='store_true', help='revoke permission from target uid')
    group.add_argument('-l', '--list', action='store_true', help='list permissions of target uid')

    parser.add_argument('-p','--perm', action='store', type=str, help='target permission name')
    parser.add_argument('-u', '--uid', action='store', type=int, required=True, help='target uid')

    args = parser.parse_args()
    
    return args

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])


def processor(perm_name, uid, mode):

    try:

        device = frida.get_usb_device()

        session = device.attach('system_server')

        with codecs.open('./grant_perm.js', 'r', 'utf-8') as f:
            source = f.read()

        script = session.create_script(source)

        script.on('message', on_message)

        script.load()

        # check if permission exists for mode grant/revoke
        if mode in ['grant', 'revoke']:
            if not perm_name:
                print('-p/--perm is required for mode : {}, exiting...'.format(mode))
                return
            perm = script.exports.get_permission(perm_name)
            if not perm:
                print('{} not exists in system, exiting...'.format(perm_name))
                return
        
        if mode == 'grant':
            script.exports.grant_perm_to_uid(perm_name, uid)
        elif mode == 'revoke':
            script.exports.revoke_perm_from_uid(perm_name, uid)
        elif mode == 'list':
            script.exports.list_perm_of_uid(uid)

        session.detach()

    except Exception as e:
        print(e, ', exiting...')


if __name__ == '__main__':

    args = parse_args()

    if args.grant:
        processor(args.perm, args.uid, 'grant')
    
    elif args.revoke:
        processor(args.perm, args.uid, 'revoke')
    
    elif args.list:
        processor(args.perm, args.uid, 'list')
    
    else:
        print('args error')
