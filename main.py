from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.metrics import dp
from kivy.utils import platform
from jnius import autoclass, cast
from kivy.uix.checkbox import CheckBox
import os
import json


class ProxyApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical',padding=dp(10), spacing=dp(5))
        button_height = '32dp'

        self.box_start= BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.start_button = Button(
            text='start proxy',
            size_hint_y=None,
            height=button_height
        )
        self.start_button.bind(on_press=self.run_proxy_service)
        self.box_start.add_widget(self.start_button)
        self.proxy_running = False
        self.vpn_check_box_hint=Label(text='Global VPN')
        self.box_start.add_widget(self.vpn_check_box_hint)
        self.vpn_checkbox = CheckBox()
        self.box_start.add_widget(self.vpn_checkbox)
        self.layout.add_widget(self.box_start)

        self.delete_cache_box= BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.delete_DNS_cache_button = Button(
            text='delete DNS cache',
            size_hint_y=None,
            height=button_height
        )
        self.delete_DNS_cache_button.bind(on_press=self.delete_DNS_cache)
        self.delete_cache_box.add_widget(self.delete_DNS_cache_button)
        self.delete_TTL_cache_button = Button(
            text='delete TTL cache',
            size_hint_y=None,
            height=button_height
        )
        self.delete_TTL_cache_button.bind(on_press=self.delete_TTL_cache)
        self.delete_cache_box.add_widget(self.delete_TTL_cache_button)
        self.layout.add_widget(self.delete_cache_box)
        
        self.config_button_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.edit_config_button = Button(
            text='Edit config',
            size_hint_y=None,
            height=button_height
        )
        self.edit_config_button.bind(on_press=self.edit_config)
        self.config_button_box.add_widget(self.edit_config_button)
        self.save_config_button = Button(
            text='Save config',
            size_hint_y=None,
            height=button_height
        )
        self.save_config_button.bind(on_press=self.save_config)
        self.save_config_button.disabled = True
        self.config_button_box.add_widget(self.save_config_button)
        self.layout.add_widget(self.config_button_box)
        self.config_input = TextInput(
            hint_text='Edit config.json',
            multiline=True,
            readonly=True,
            size_hint_y=1
        )
        self.layout.add_widget(self.config_input)
        
        return self.layout

    def on_start(self):
        self.get_permit()
        self.load_config()
            

    def edit_config(self,instance):
        if self.config_input.readonly:
            self.config_input.readonly = False
            self.edit_config_button.text = 'Lock config'
            self.config_editable = False
            self.save_config_button.disabled = False
        else:
            self.config_input.readonly = True
            self.edit_config_button.text = 'Edit config'
            self.config_editable = True
            self.save_config_button.disabled = True

    def load_config(self):
        config_path = 'config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    self.config_input.text = json.dumps(json.load(f), indent=4)
            except Exception as e:
                print(f"Failed to load config: {e}")
                failded_popup = Popup(title='Load config failed', content=Label(text=f"Failed to load config: {e}"), size_hint=(None, None))
                failded_popup.open()
                raise e
        else:
            self.config_input.text = json.dumps(
                self.get_default_config(), indent=4)

    def start_proxy_service(self):
        """启动Android服务来运行代理"""
        from android import mActivity
        # print('Service started____ ', nm)
        context = mActivity.getApplicationContext()

        SERVICE_NAME = str(context.getPackageName()) + \
            '.Service' + 'Proxyservice'

        self.service_target = autoclass(SERVICE_NAME)

        self.service_target.start(
            mActivity, 'icon', 'TlsFragment', 'ProxyRunning', '')
        
        success_popup = Popup(title='Start successfully', content=Label(text='Proxy started successfully'), size_hint=(None, None))
        success_popup.open()

        return self.service_target


    def stop_proxy_service(self):
        from android import mActivity
        context = mActivity.getApplicationContext()

        SERVICE_NAME = str(context.getPackageName()) + \
            '.Service' + 'Proxyservice'

        Service = autoclass(SERVICE_NAME)

        Intent = autoclass('android.content.Intent')
        service_intent = Intent(mActivity, Service)

        mActivity.stopService(service_intent)


    def get_permit(self):
        from android.permissions import Permission, request_permissions

        def callback(permissions, results):
            granted_permissions = [perm for perm,
                                    res in zip(permissions, results) if res]
            denied_permissions = [perm for perm, res in zip(
                permissions, results) if not res]

            if denied_permissions:
                print('Denied permissions:', denied_permissions)

            elif granted_permissions:
                print('Got all permissions')
            else:
                lack_permissions_popup = Popup(title='Lack of permissions', content=Label(text='Please grant all permissions to use this app'), size_hint=(None, None))
                lack_permissions_popup.open()

        requested_permissions = [
            Permission.INTERNET,
            Permission.FOREGROUND_SERVICE,
            Permission.READ_EXTERNAL_STORAGE,
            Permission.SYSTEM_ALERT_WINDOW,
        ]
        request_permissions(requested_permissions, callback)

    def run_proxy_service(self,instance):
        if self.proxy_running:
            try:
                self.start_button.disabled = True
                self.start_button.text= 'Stopping'
                self.stop_proxy_service()
                self.start_button.text = 'start proxy'
                self.start_button.disabled = False
                # 启用其余组件
                self.vpn_checkbox.disabled = False
                self.config_button_box.disabled = False
                self.config_input.disabled = False
                self.delete_cache_box.disabled = False
                self.proxy_running = False
            except Exception as e:
                faild_popup=Popup(title='Stop failed', content=Label(text='Failed to stop proxy'), size_hint=(None, None))
                faild_popup.open()
                self.start_button.text = 'stop proxy'
                raise e
        else:
            try:
                self.start_button.disabled = True
                self.start_button.text = 'starting'
                self.start_proxy_service()
                self.start_button.text = 'stop proxy'
                self.start_button.disabled = False
                self.vpn_checkbox.disabled=True
                self.config_button_box.disabled = True
                self.config_input.disabled = True
                self.delete_cache_box.disabled = True
                self.proxy_running = True
            except Exception as e:
                faild_popup= Popup(title='Start failed', content=Label(text='Failed to start proxy service'), size_hint=(None, None))
                faild_popup.open()
                self.start_button.text = 'Start proxy'
                raise e


    def save_config(self,instance):
        try:
            config_data = json.loads(self.config_input.text)
            with open('config.json', 'w') as f:
                json.dump(config_data, f, indent=4)
            success_popup = Popup(title='Save config success', content=Label(text='Config has been saved successfully'), size_hint=(None, None))
            success_popup.open()
        except json.JSONDecodeError:
            invaild_popup = Popup(title='Invalid JSON format', content=Label(text='Please input valid JSON format'), size_hint=(None, None))
            invaild_popup.open()
        except Exception as e:
            failded_popup = Popup(title='Save config failed', content=Label(text=f"Failed to save config: {e}"), size_hint=(None, None))
            failded_popup.open()
            raise e

    def delete_DNS_cache(self,instance):
        try:
            # 删除DNS_cache.json
            if os.path.exists('DNS_cache.json'):
                os.remove('DNS_cache.json')
                success_popup = Popup(title='Delete DNS cache success', content=Label(text='DNS_cache.json has been deleted successfully'), size_hint=(None, None))
                success_popup.open()
        except Exception as e:
            failded_popup = Popup(title='delete DNS cache failed', content=Label(text='Failed to delete DNS_cache.json'), size_hint=(None, None))
            failded_popup.open()
            raise e

    def delete_TTL_cache(self,instance):
        try:
            # 删除TTL_cache.json
            if os.path.exists('TTL_cache.json'):
                os.remove('TTL_cache.json')
                success_popup = Popup(title='Delete TTL cache success', content=Label(text='TTL_cache.json has been deleted successfully'), size_hint=(None, None))
                success_popup.open()
        except Exception as e:
            failded_popup = Popup(title='Delete TTL cache failed', content=Label(text='Failed to delete TTL_cache.json'), size_hint=(None, None))
            failded_popup.open()
            raise e

if __name__ == '__main__':
    ProxyApp().run()
