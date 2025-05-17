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
        layout = BoxLayout(orientation='vertical',
                           padding=dp(10), spacing=dp(5))
        button_height = '32dp'

        self.box_start= BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.start_button = Button(
            text='启动代理',
            size_hint_y=None,
            height=button_height
        )
        self.start_button.bind(on_press=self.run_proxy_service)
        self.box_start.add_widget(self.start_button)
        self.proxy_running = False
        self.vpn_check_box_hint=Label(texy='全局vpn模式')
        self.box_start.add_widget(self.vpn_check_box_hint)
        self.vpn_checkbox = CheckBox()
        self.vpn_mode=False
        self.vpn_checkbox.bind(self.vpn_mode)
        self.box_start.add_widget(self.vpn_checkbox)
        self.layout.add_widget(self.box_start)

        self.delete_cache_box= BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.delete_DNS_cache_button = Button(
            text='删除DNS缓存',
            size_hint_y=None,
            height=button_height
        )
        self.delete_DNS_cache_button.bind(on_press=self.delete_DNS_cache)
        self.delete_cache_box.add_widget(self.delete_DNS_cache_button)
        self.delete_TTL_cache_button = Button(
            text='删除TTL缓存',
            size_hint_y=None,
            height=button_height
        )
        self.delete_TTL_cache_button.bind(on_press=self.delete_TTL_cache)
        self.delete_cache_box.add_widget(self.delete_TTL_cache_button)
        layout.add_widget(self.delete_cache_box)
        
        self.config_box = BoxLayout(orientation='vertical', size_hint_y=None, height=button_height)
        self.config_button_box = BoxLayout(orientation='horizontal', size_hint_y=None, height=button_height)
        self.edit_config_button = Button(
            text='编辑配置',
            size_hint_y=None,
            height=button_height
        )
        self.edit_config_button.bind(on_press=self.edit_config)
        self.config_editable=False
        self.config_button_box.add_widget(self.edit_config_button)
        self.save_config_button = Button(
            text='保存配置',
            size_hint_y=None,
            height=button_height
        )
        self.save_config_button.bind(on_press=self.save_config)
        self.save_config_button.disabled = True
        self.config_button_box.add_widget(self.save_config_button)
        self.config_box.add_widget(self.config_button_box)
        self.config_input = TextInput(
            hint_text='请输入配置',
            multiline=True,
            size_hint_y=1
        )
        self.config_input.readonly = True
        self.config_box.add_widget(self.config_input)
        layout.add_widget(self.config_box)
    
        return layout

    def on_start(self):
        self.load_config()
        self.get_permit()

    def edit_config(self):
        if self.config_editable:
            self.config_input.readonly = False
            self.edit_config_button.text = '锁定配置'
            self.config_editable = False
            self.save_config_button.disabled = False
        else:
            self.config_input.readonly = True
            self.edit_config_button.text = '编辑配置'
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
                failded_popup = Popup(title='加载配置失败', content=Label(text=f"Failed to load config: {e}"), size_hint=(None, None), size=(400, 200))
                failded_popup.open()
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
            mActivity, 'icon', 'TlsFragment', '正在运行代理 ProxyRunning', '')
        
        success_popup = Popup(title='启动代理成功', content=Label(text='Proxy started successfully'), size_hint=(None, None), size=(400, 200))
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
                lack_permissions_popup = Popup(title='缺乏一些权限，可能无法正常运行', content=Label(text='Please grant all permissions to use this app'), size_hint=(None, None), size=(400, 200))
                lack_permissions_popup.open()

        requested_permissions = [
            Permission.INTERNET,
            Permission.FOREGROUND_SERVICE,
            Permission.READ_EXTERNAL_STORAGE,
            Permission.SYSTEM_ALERT_WINDOW,
        ]
        request_permissions(requested_permissions, callback)

    def run_proxy_service(self):
        if self.proxy_running:
            try:
                self.start_button.text= '正在停止'
                self.stop_proxy_service()
                self.start_button.text = '启动代理'
                self.start_button.disabled = False
                # 启用其余组件
                self.vpn_checkbox.disabled = False
                self.config_box.disabled = False
                self.delete_cache_box.disabled = False
                self.proxy_running = False
            except:
                faild_popup=Popup(title='停止代理失败', content=Label(text='Failed to stop proxy'), size_hint=(None, None), size=(400, 200))
                faild_popup.open()
                self.start_button.text = '停止代理'
        else:
            try:
                self.start_button.text = '正在启动'
                self.start_proxy_service()
                self.start_button.text = '停止代理'
                self.start_button.disabled = False
                self.vpn_checkbox=True
                self.config_box.disabled = True
                self.delete_cache_box.disabled = True
                self.proxy_running = True
            except:
                faild_popup= Popup(title='启动失败', content=Label(text='Failed to start proxy service'), size_hint=(None, None), size=(400, 200))
                faild_popup.open()
                self.start_button.text = '启动代理'


    def save_config(self):
        try:
            config_data = json.loads(self.config_input.text)
            with open('config.json', 'w') as f:
                json.dump(config_data, f, indent=4)
            print("Configuration saved successfully.")
        except json.JSONDecodeError:
            print("Invalid JSON format, please check your configuration")
        except Exception as e:
            print(f"Failed to save config: {e}")

    def delete_DNS_cache(self):
        try:
            # 删除DNS_cache.json
            if os.path.exists('DNS_cache.json'):
                os.remove('DNS_cache.json')
                success_popup = Popup(title='删除DNS缓存成功', content=Label(text='DNS_cache.json has been deleted successfully'), size_hint=(None, None), size=(400, 200))
                success_popup.open()
        except:
            failded_popup = Popup(title='删除DNS缓存失败', content=Label(text='Failed to delete DNS_cache.json'), size_hint=(None, None), size=(400, 200))
            failded_popup.open()

    def delete_TTL_cache(self):
        try:
            # 删除TTL_cache.json
            if os.path.exists('TTL_cache.json'):
                os.remove('TTL_cache.json')
                success_popup = Popup(title='删除TTL缓存成功', content=Label(text='TTL_cache.json has been deleted successfully'), size_hint=(None, None), size=(400, 200))
                success_popup.open()
        except:
            failded_popup = Popup(title='删除TTL缓存失败', content=Label(text='Failed to delete TTL_cache.json'), size_hint=(None, None), size=(400, 200))
            failded_popup.open()

if __name__ == '__main__':
    ProxyApp().run()
