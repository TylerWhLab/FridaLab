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
        
        Java.choose("uk.rossmarks.fridalab.MainActivity", {
            onMatch: function(instance) {
                send('[*] Instance found  : ' + instance.toString());
                const checkid = instance.findViewById(2131165231);
                const check = Java.cast(checkid, Java.use("android.widget.Button")); // button 객체로 형변환
                const String = Java.use("java.lang.String");
                check.setText(String.$new("Confirm"));
                
                // $new : 클래스 객체를 인스턴스화 해줌. 인스턴스로 접근해야 실제로 실행이 됨
                
                /* setText 에는 단순히 ""로 감싼 문자열을 넣는다고 되는것이 아니고, 아래 클래스로 형을 맞춰줘야함
                Error: setText(): argument types do not match any of:
                    .overload('java.lang.CharSequence') // java.lang.String 과 동일함
                    .overload('int')
                    .overload('java.lang.CharSequence', 'android.widget.TextView$BufferType')
                    .overload('int', 'android.widget.TextView$BufferType')
                    .overload('[C', 'int', 'int')
                    .overload('java.lang.CharSequence', 'android.widget.TextView$BufferType', 'boolean', 'int')
                */
                
                
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


# Error: android.view.ViewRootImpl$CalledFromWrongThreadException: Only the original thread that created a view hierarchy can touch its views.
# 에러는 항상 뜨는데, ui 변경 시 뜨는 에러. 이 문제 풀이에는 영향을 미치지 않음