import frida, sys

# String received from js send()
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['description'])
    else:
        print(message)


def before_load():
    device = frida.get_usb_device()        # USB device connect
    pid = device.spawn([package])          # Creating PS on USB device
    session = device.attach(pid)           # PS connect
    script = session.create_script(jscode) # Create script for use in frida
    script.on('message', on_message)       # Receive from js send()
    script.load()                          # Load script before the main thread runs 
    device.resume(pid)                     # PS main thread execute
    sys.stdin.read()                       # Prevent problems that terminate before script operation


def after_load():
    session = frida.get_usb_device().attach(package) # Running PS connection
    script = session.create_script(jscode)           # Same as before_load()
    script.on('message', on_message)                 # Same as before_load()
    script.load()                                    # Same as before_load()
    sys.stdin.read()                                 # Same as before_load()
    

def main():
    try:
        after_load()
    except frida.ProcessNotFoundError: 
        before_load()


package = 'uk.rossmarks.fridalab'
jscode = """
setImmediate(function(){
    Java.perform(function(){
        const obj = Java.use("uk.rossmarks.fridalab.challenge_07");
        send('[v] Complete class obj search');
        
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function(instance) {
                send('[*] Instance found  : ' + instance.toString());
                for(var i = 9999; i>=1000; i--){
                    var tmp = String(i);
                    send(tmp);
                    if(obj.check07Pin(tmp)){
                        instance.chall07(tmp);
                        break;
                    }
                }
                
            },
            onComplete: function() {
                send('[*] Finish instance search');
            }
        })
        
    })
})
"""


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nterminated!\n')
