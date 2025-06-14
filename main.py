from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.metrics import dp
from kivy.utils import platform
from jnius import autoclass
from kivy.uix.checkbox import CheckBox
import os
import json

config_mirror_list= ["https://raw.bgithub.xyz/maoist2009/TlsFragment/refs/heads/main/config.json","https://raw.githubusercontent.com/maoist2009/TlsFragment/refs/heads/main/config.json"]


class ProxyApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(5))
        button_height = dp(32)  # Use numeric value directly

        self.box_start = BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.start_button = Button(
            text='start proxy',
            size_hint_y=None,
            height=button_height
        )
        self.start_button.bind(on_press=self.run_proxy_service)
        self.box_start.add_widget(self.start_button)

        self.proxy_running = False
        self.layout.add_widget(self.box_start)

        self.show_in_edit="config.json"
        self.file_list_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.config_file_button = Button(
            text='config',
            size_hint_y=None,
            height=button_height
        )
        self.DNS_cache_file_button = Button(
            text='DNS cache',
            size_hint_y=None,
            height=button_height
        )
        self.TTL_cache_file_button = Button(
            text='TTL cache',
            size_hint_y=None,
            height=button_height
        )
        self.config_file_button.bind(on_press=self.edit_config)
        self.DNS_cache_file_button.bind(on_press=self.edit_DNS_cache)
        self.TTL_cache_file_button.bind(on_press=self.edit_TTL_cache)
        self.file_list_box.add_widget(self.config_file_button)
        self.file_list_box.add_widget(self.DNS_cache_file_button)
        self.file_list_box.add_widget(self.TTL_cache_file_button)
        self.layout.add_widget(self.file_list_box)


        self.config_button_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.save_config_button = Button(
            text='Save',
            size_hint_y=None,
            height=button_height
        )
        self.save_config_button.bind(on_press=self.save_file)
        self.config_button_box.add_widget(self.save_config_button)
        self.layout.add_widget(self.config_button_box)

        self.button_try_to_update_config=Button(
            text='Try to update config',
            size_hint_y=None,
            height=button_height
        )
        self.button_try_to_update_config.bind(on_press=self.try_to_update_config)
        self.layout.add_widget(self.button_try_to_update_config)

        self.config_input = TextInput(
            hint_text='Edit Here',
            multiline=True,
            size_hint_y=1
        )
        self.layout.add_widget(self.config_input)

        return self.layout

    def try_to_update_config(self, instance):
        import requests

        succeeded= False
        # 改为轮询list中url
        for url in config_mirror_list:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    config_data = json.loads(response.text)
                    with open('config.json', 'w') as f:
                        json.dump(config_data, f, indent=4)
                    succeeded = True
                    self.load_file()
                    self.show_popup('Update success', 'Config file updated successfully. You may need to restart proxy. ')
                    break
            except:
                pass
        if not succeeded:
            self.show_popup('Update failed', 'Failed to update config file')


    def edit_config(self, instance):
        self.show_in_edit="config.json"
        self.load_file()
    
    def edit_DNS_cache(self, instance):
        self.show_in_edit="DNS_cache.json"
        self.load_file()

    def edit_TTL_cache(self, instance):
        self.show_in_edit="TTL_cache.json"
        self.load_file()

    def on_start(self):
        self.get_permit()
        self.load_file()

    def show_popup(self, title, message):
        """Utility function to show popups."""
        popup = Popup(title=title, content=Label(text=message), size=(dp(200), dp(40)))
        popup.open()

    def load_file(self):
        path=self.show_in_edit
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.config_input.text = f.read()
            except Exception as e:
                self.show_popup('Load file failed', f"Failed to load file: {e}")
                self.config_input.text = ''
        else:
            self.show_popup('File not found', f"File {path} not found")

    
    def save_file(self,instance):
        path=self.show_in_edit
        if os.path.exists(path):
            try:
                config_data = json.loads(self.config_input.text)
                with open(path, 'w') as f:
                    json.dump(config_data, f, indent=4)
                self.show_popup('Save file success', f"File {path} has been saved successfully")
            except json.JSONDecodeError:
                self.show_popup('Invalid JSON format', 'Please input valid JSON format')
            except Exception as e:
                self.show_popup('Save file failed', f"Failed to save file: {e}")
        else:
            self.show_popup('File not found', f"File {path} not found")


    def start_proxy_service(self):
        """Start the Android service to run the proxy."""
        from android import mActivity
        context = mActivity.getApplicationContext()
        SERVICE_NAME = str(context.getPackageName()) + '.ServiceProxyservice'

        self.service_target = autoclass(SERVICE_NAME)
        self.service_target.start(mActivity, 'small_icon.png', 'TlsFragment', 'TlsFragment Proxy Foreground Service Running', '')
        self.show_popup('Start successfully', 'Proxy started successfully')

        return self.service_target

    def stop_proxy_service(self):
        from android import mActivity
        context = mActivity.getApplicationContext()
        SERVICE_NAME = str(context.getPackageName()) + '.ServiceProxyservice'
        Service = autoclass(SERVICE_NAME)
        Intent = autoclass('android.content.Intent')
        service_intent = Intent(mActivity, Service)
        mActivity.stopService(service_intent)

    def get_permit(self):
        from android.permissions import Permission, request_permissions

        def callback(permissions, results):
            granted_permissions = [perm for perm, res in zip(permissions, results) if res]
            denied_permissions = [perm for perm, res in zip(permissions, results) if not res]

            if denied_permissions:
                print('Denied permissions:', denied_permissions)
            elif granted_permissions:
                print('Got all permissions')
            else:
                self.show_popup('Lack of permissions', 'Please grant all permissions to use this app')

        requested_permissions = [
            Permission.INTERNET,
            Permission.FOREGROUND_SERVICE,
            Permission.READ_EXTERNAL_STORAGE,
            Permission.SYSTEM_ALERT_WINDOW,
        ]
        request_permissions(requested_permissions, callback)

    def run_proxy_service(self, instance):
        if self.proxy_running:
            try:
                self.start_button.disabled = True
                self.start_button.text = 'Stopping'
                self.stop_proxy_service()
                self.start_button.text = 'start proxy'
                self.start_button.disabled = False
                self.config_button_box.disabled = False
                self.config_input.disabled = False
                self.proxy_running = False
            except Exception as e:
                self.show_popup('Stop failed', 'Failed to stop proxy')
                self.start_button.text = 'stop proxy'
                self.start_button.disabled=False
        else:
            try:
                self.start_button.disabled = True
                self.start_button.text = 'starting'
                self.start_proxy_service()
                self.start_button.text = 'stop proxy'
                self.start_button.disabled = False
                self.config_button_box.disabled = True
                self.config_input.disabled = True
                self.proxy_running = True
            except Exception as e:
                self.show_popup('Start failed', 'Failed to start proxy service')
                self.start_button.text = 'Start proxy'
                self.start_button.disabled=False


if __name__ == '__main__':
    ProxyApp().run()
