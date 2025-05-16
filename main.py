from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.metrics import dp
from kivy.utils import platform
from jnius import autoclass, cast
import os
import json

class ProxyApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(5))
        button_height = '32dp'
        
        self.start_button = Button(
            text='Start Proxy',
            size_hint_y=None,
            height=button_height
        )
        self.start_button.bind(on_press=self.start_proxy_service)
        layout.add_widget(self.start_button)

        self.stop_button = Button(
            text='Stop Proxy',
            size_hint_y=None,
            height=button_height
        )
        self.stop_button.bind(on_press=self.stop_proxy_service)
        layout.add_widget(self.stop_button)

        self.save_button = Button(
            text='Save Config',
            size_hint_y=None,
            height=button_height
        )
        self.save_button.bind(on_press=self.save_config)
        layout.add_widget(self.save_button)

        self.config_input = TextInput(
            hint_text='Edit config.json', 
            multiline=True,
            size_hint_y=1
        )
        layout.add_widget(self.config_input)

        self.get_permit()
        
        return layout

    def on_start(self):
        self.load_config()
        self.check_service_status()

    def load_config(self):
        config_path = 'config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.config_input.text = json.dumps(json.load(f), indent=4)
            except Exception as e:
                print(f"Failed to load config: {e}")
        else:
            self.config_input.text = json.dumps(self.get_default_config(), indent=4)

    def start_proxy_service(self, instance):
        """启动Android服务来运行代理"""
        try:
            from android import mActivity
            #print('Service started____ ', nm)
            context =  mActivity.getApplicationContext()

            SERVICE_NAME = str(context.getPackageName()) + '.Service' + 'ProxyService'

            self.service_target = autoclass(SERVICE_NAME)

            self.service_target.start(mActivity,'icon', 'logger', 'Connecting', '')

            return self.service_target
            
        except Exception as e:
            print(f"Failed to start service: {e}")
            import traceback
            traceback.print_exc()

    def stop_proxy_service(self, instance):
        """停止代理服务"""
        try:
            from android import mActivity
            context = mActivity.getApplicationContext()


            SERVICE_NAME = str(context.getPackageName()) + '.Service' + 'ProxyService'

            Service = autoclass(SERVICE_NAME)

            Intent = autoclass('android.content.Intent')
            service_intent = Intent(mActivity, Service)


            mActivity.stopService(service_intent)
            
        except Exception as e:
            print(f"Failed to stop service: {e}")

    def check_service_status(self):
        """检查服务状态"""
        try:
            PythonService = autoclass('org.kivy.android.PythonService')
            service = PythonService.mService
            
            # 检查服务是否正在运行
            is_running = service.isServiceRunning()
            
            self.start_button.disabled = is_running
            self.stop_button.disabled = not is_running
            
        except Exception as e:
            print(f"Failed to check service status: {e}")

    def get_permit(self):
        if platform == 'android':
            from android.permissions import Permission, request_permissions 

            def callback(permissions, results):
                granted_permissions = [perm for perm, res in zip(permissions, results) if res]
                denied_permissions = [perm for perm, res in zip(permissions, results) if not res]

                if denied_permissions:
                    print('Denied permissions:', denied_permissions)

                elif granted_permissions:
                    print('Got all permissions')
                else:
                    print('No permissions were granted or denied')

            requested_permissions = [
                Permission.INTERNET,
                Permission.FOREGROUND_SERVICE,
                Permission.READ_EXTERNAL_STORAGE,
                Permission.SYSTEM_ALERT_WINDOW
            ]
            request_permissions(requested_permissions, callback)
    def save_config(self, instance):
        try:
            config_data = json.loads(self.config_input.text)
            with open('config.json', 'w') as f:
                json.dump(config_data, f, indent=4)
            print("Configuration saved successfully.")
        except json.JSONDecodeError:
            print("Invalid JSON format, please check your configuration")
        except Exception as e:
            print(f"Failed to save config: {e}")

if __name__ == '__main__':
    ProxyApp().run()