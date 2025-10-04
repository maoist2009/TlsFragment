from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp
from kivy.utils import platform
from jnius import autoclass, cast
from kivy.uix.checkbox import CheckBox
import os
import json
import android

config_mirror_list = [
    "https://raw.bgithub.xyz/maoist2009/TlsFragment/refs/heads/main/",
    "https://raw.githubusercontent.com/maoist2009/TlsFragment/refs/heads/main/",
]


class ProxyApp(App):
    def build(self):
        self.layout = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(5))
        button_height = dp(32)  # Use numeric value directly

        self.box_start = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=button_height
        )
        self.start_button = Button(
            text="start proxy", size_hint_y=None, height=button_height
        )
        self.start_button.bind(on_press=self.run_proxy_service)
        self.box_start.add_widget(self.start_button)

        self.proxy_running = False
        self.layout.add_widget(self.box_start)

        self.show_in_edit = "config.json"
        button_heightm2=button_height*2
        self.file_list_box = BoxLayout(
            orientation="vertical", size_hint_y=None, height=button_heightm2
        )
        self.file_list_box_sub1 = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=button_height
        )
        self.file_list_box_sub2 = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=button_height
        )    
        self.config_file_button = Button(
            text="config", size_hint_y=None, height=button_height
        )
        self.config_extra_file_button = Button(
            text="extra config", size_hint_y=None, height=button_height
        )
        self.DNS_cache_file_button = Button(
            text="DNS cache", size_hint_y=None, height=button_height
        )
        self.TTL_cache_file_button = Button(
            text="TTL cache", size_hint_y=None, height=button_height
        )
        self.config_file_button.bind(on_press=self.edit_config)
        self.config_extra_file_button.bind(on_press=self.edit_config_extra)
        self.DNS_cache_file_button.bind(on_press=self.edit_DNS_cache)
        self.TTL_cache_file_button.bind(on_press=self.edit_TTL_cache)
        self.file_list_box_sub1.add_widget(self.config_file_button)
        self.file_list_box_sub1.add_widget(self.config_extra_file_button)
        self.file_list_box_sub2.add_widget(self.DNS_cache_file_button)
        self.file_list_box_sub2.add_widget(self.TTL_cache_file_button)
        self.file_list_box.add_widget(self.file_list_box_sub1)
        self.file_list_box.add_widget(self.file_list_box_sub2)
        self.layout.add_widget(self.file_list_box)

        self.config_button_box = BoxLayout(
            orientation="horizontal", size_hint_y=None, height=button_height
        )
        self.save_config_button = Button(
            text="Save", size_hint_y=None, height=button_height
        )
        self.save_config_button.bind(on_press=self.save_file)
        self.config_button_box.add_widget(self.save_config_button)
        self.layout.add_widget(self.config_button_box)

        self.button_try_to_update_config = Button(
            text="Try to update file", size_hint_y=None, height=button_height
        )
        self.button_try_to_update_config.bind(on_press=self.try_to_update_config)
        self.layout.add_widget(self.button_try_to_update_config)

        self.config_input = TextInput(
            hint_text="Edit Here",
            multiline=True,
            size_hint_y=1,
            auto_indent=True,  # 自动缩进
            replace_crlf=True,  # 替换换行符为 \n
            cursor_blink=True,  # 光标闪烁
            cursor_width=dp(2),  # 设置光标宽度
        )
        self.layout.add_widget(self.config_input)

        return self.layout

    def try_to_update_config(self, instance):
        import requests

        succeeded = False
        # 改为轮询list中url
        for url in config_mirror_list:
            try:
                response = requests.get(url+self.show_in_edit)
                if response.status_code == 200:
                    config_data = json.loads(response.text)
                    with open(self.show_in_edit, "w") as f:
                        json.dump(config_data, f, indent=4)
                    succeeded = True
                    self.load_file()
                    self.show_popup(
                        "Update success",
                        f"{self.show_in_edit} updated successfully.  \nYou may need to restart proxy. "
                    )
                    break
            except:
                pass
        if self.is_service_running() and not succeeded:
            proxy = {"http": f"http://127.0.0.1:{self.proxy_port}"}
            for url in config_mirror_list:
                try:
                    response = requests.get(url+self.show_in_edit, proxies=proxy)
                    if response.status_code == 200:
                        config_data = json.loads(response.text)
                        with open(self.show_in_edit, "w") as f:
                            json.dump(config_data, f, indent=4)
                        succeeded = True
                        self.load_file()
                        self.show_popup(
                            "Update success",
                            f"{self.show_in_edit} updated successfully.  \nYou may need to restart proxy. "
                        )
                        break
                except:
                    pass
        if not succeeded:
            self.show_popup("Update failed", f"Failed to update {self.show_in_edit}")
        else:
            self.get_port_from_config()

    def get_port_from_config(self):
        try:
            path = "config.json"
            with open(path, "r") as f:
                json_str = f.read()
            data = json.loads(json_str)  # 将字符串解析为字典
            self.proxy_port = data["port"]  # 获取 port 的值
        except:
            self.show_popup("config error","Failed to get port from config.json")
            self.proxy_port = 2500

    def is_service_running(self):
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", self.proxy_port))
            sock.close()
            return result == 0

    def edit_config(self, instance):
        self.show_in_edit = "config.json"
        self.load_file()
    
    def edit_config_extra(self, instance):
        self.show_in_edit = "config_extra.json"
        self.load_file()

    def edit_DNS_cache(self, instance):
        self.show_in_edit = "DNS_cache.json"
        self.load_file()

    def edit_TTL_cache(self, instance):
        self.show_in_edit = "TTL_cache.json"
        self.load_file()

    def on_start(self):
        try:
            self.request_battery_optimization()
            self.get_permit()
            self.load_file()
        except:
            pass
        if self.is_service_running():
            self.run_proxy_service(None, False)

    def load_file(self):
        path = self.show_in_edit
        if self.show_in_edit == "config_pac.json":
            self.show_popup("warning","Too big, can't show. ")
            self.config_input.text = "Too big, can't show."
            return
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    self.config_input.text = f.read()
                if path == "config.json":
                    self.get_port_from_config()
            except Exception as e:
                self.show_popup("Load file failed", f"Failed to load file: {e}")
                self.config_input.text = "{}"
        else:
            self.show_popup("File not found", f"File {path} not found")

    def save_file(self, instance):
        path = self.show_in_edit
        if self.config_input.text == "Too big, can't show.":
            self.show_popup("Warning", "You can't save it. ")
            return
        if os.path.exists(path):
            try:
                if self.config_input.text == "":
                    self.config_input.text = "{}"
                config_data = json.loads(self.config_input.text)
                with open(path, "w") as f:
                    json.dump(config_data, f, indent=4)
                self.show_popup(
                    "Save file success", f"File {path} has been saved successfully"
                )
            except json.JSONDecodeError:
                self.show_popup("Invalid JSON format", "Please input valid JSON format")
            except Exception as e:
                self.show_popup("Save file failed", f"Failed to save file: {e}")
        else:
            self.show_popup("File not found", f"File {path} not found")

    def show_popup(self, title, message, callback=None):
        # 创建垂直布局，设置外边距和间距
        layout = BoxLayout(orientation="vertical")

        # 创建 Label，支持自动换行
        label = Label(
            text=message,
            halign="left",
            valign="top",
            font_size=dp(14),
            text_size=(dp(330), None),  # 根据弹窗宽度调整
            size_hint_y=None,
        )
        label.bind(texture_size=label.setter("size"))  # 自动调整高度

        # 创建 ScrollView，填充整个可用空间
        scroll_view = ScrollView(
            size_hint=(1, 1),  # 填充剩余空间
            bar_width=dp(8),  # 滚动条宽度（可选）
            bar_color=[0.2, 0.6, 1, 0.8],  # 滚动条颜色（可选）
            scroll_type=["bars", "content"],  # 滚动类型（可选）
        )
        scroll_view.add_widget(label)

        # 创建 OK 按钮
        ok_button = Button(text="OK", size_hint_y=None, height=dp(48), font_size=dp(16))

        # 添加组件到布局
        layout.add_widget(scroll_view)
        layout.add_widget(ok_button)

        # 创建弹窗
        popup = Popup(
            title=title, content=layout, size=(dp(350), dp(350)), size_hint=(None, None)
        )

        # 绑定按钮仅用于关闭弹窗
        ok_button.bind(on_release=popup.dismiss)

        # 绑定弹窗关闭事件，执行回调
        if callback:
            popup.bind(on_dismiss=lambda instance: callback())

        # 显示弹窗
        popup.open()

    def start_proxy_service(self):
        from android import mActivity
        from android.permissions import Permission

        SDK_INT = autoclass('android.os.Build$VERSION').SDK_INT
        if SDK_INT >= 33:
            self.get_permit([Permission.POST_NOTIFICATIONS])

        context = mActivity.getApplicationContext()
        SERVICE_NAME = str(context.getPackageName()) + ".ServiceProxyservice"
        service = autoclass(SERVICE_NAME)
        service.start(
            mActivity,
            "notification_icon",   # ← 与 android.add_resources 中的文件名一致（不含 .png）
            "TlsFragment",
            "Proxy is running",
            ""             # kivy 会自动创建，传了也没用
        )

    def stop_proxy_service(self):
        from android import mActivity

        context = mActivity.getApplicationContext()
        SERVICE_NAME = str(context.getPackageName()) + ".ServiceProxyservice"
        Service = autoclass(SERVICE_NAME)
        Intent = autoclass("android.content.Intent")
        service_intent = Intent(mActivity, Service)
        mActivity.stopService(service_intent)
        while self.is_service_running():
            pass

    def is_battery_optimization_ignored(self):
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        Context = autoclass("android.content.Context")
        PowerManager = autoclass("android.os.PowerManager")

        context = PythonActivity.mActivity.getApplicationContext()
        power_manager = cast(
            PowerManager, context.getSystemService(Context.POWER_SERVICE)
        )

        if power_manager:
            package_name = context.getPackageName()
            return power_manager.isIgnoringBatteryOptimizations(package_name)
        return False

    def show_battery_optimization_popup(self):
        # 获取安卓类
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        Intent = autoclass("android.content.Intent")
        Settings = autoclass("android.provider.Settings")
        Uri = autoclass("android.net.Uri")

        # 构建意图
        intent = Intent()
        intent.setAction(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
        package_uri = Uri.fromParts(
            "package", PythonActivity.mActivity.getPackageName(), None
        )
        intent.setData(package_uri)

        # 启动意图
        PythonActivity.mActivity.startActivity(intent)

    def request_battery_optimization(self):
        if not self.is_battery_optimization_ignored():
            self.show_popup(
                "Keep Alive",
                "The programme runs in the background. \nTo keep it alive, please select: \n Ignore Battery optimization. \nSome Chinese UI may not work, then you need to open it manually. \nAdditionally, Please allow creating notification to allow the application start a foreground service. \nSome Chinese UI requires you open it manually too. ",
                self.show_battery_optimization_popup,
            )
        else:
            print("battery optimization turnned of")

    def get_permit(self, g_per=None):
        from android.permissions import Permission, request_permissions

        def callback(permissions, results):
            granted_permissions = [
                perm for perm, res in zip(permissions, results) if res
            ]
            denied_permissions = [
                perm for perm, res in zip(permissions, results) if not res
            ]

            if denied_permissions:
                print("Denied permissions:", denied_permissions)
            elif granted_permissions:
                print("Got all permissions")
            else:
                self.show_popup(
                    "Lack of permissions",
                    "Please grant all permissions to use this app",
                )
        if g_per:
            requested_permissions = g_per
        else:
            requested_permissions = [
                Permission.INTERNET,
                Permission.FOREGROUND_SERVICE,
                Permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
            ]
        
        request_permissions(requested_permissions, callback)

    def run_proxy_service(self, instance, change=True):
        if self.proxy_running:
            try:
                self.start_button.text = "Stopping"
                self.start_button.disabled = True
                if change:
                    self.stop_proxy_service()
                self.start_button.text = "start proxy"
                self.start_button.disabled = False
                self.config_button_box.disabled = False
                self.config_input.disabled = False
                self.proxy_running = False
            except Exception as e:
                self.show_popup("Stop failed", "Failed to stop proxy")
                self.start_button.text = "stop proxy"
                self.start_button.disabled = False
        else:
            try:
                self.start_button.text = "starting"
                self.start_button.disabled = True
                if change:
                    self.start_proxy_service()
                self.start_button.text = "stop proxy"
                self.start_button.disabled = False
                self.config_button_box.disabled = True
                self.config_input.disabled = True
                self.proxy_running = True
            except Exception as e:
                self.show_popup("Start failed", "Failed to start proxy service")
                self.start_button.text = "Start proxy"
                self.start_button.disabled = False


if __name__ == "__main__":
    ProxyApp().run()
