from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from jnius import autoclass
import os
import json
from src.tls_fragment.cli import start_server,stop_server

class ProxyApp(App):
    def build(self):
        print("buildimg")
        layout = BoxLayout(orientation='vertical')

        self.start_button = Button(text='Start Proxy')
        self.start_button.bind(on_press=self.start_proxy)
        layout.add_widget(self.start_button)

        self.stop_button = Button(text='Stop Proxy')
        stop_button.bind(on_press=self.stop_proxy)
        layout.add_widget(self.stop_button)

        self.save_button = Button(text='Save Config')
        self.save_button.bind(on_press=self.save_config)
        layout.add_widget(self.save_button)

        self.config_input = TextInput(hint_text='Edit config.json', multiline=True)
        layout.add_widget(self.config_input)

        print("built")

        # 读取默认配置文件并加载到文本框
        self.load_config()

        self.start_foreground_service()  # 启动前台服务

        return layout

    def start_proxy(self):
        start_server(block=False)

    def stop_proxy(self):
        stop_server(wait_for_stop=True)


    def load_config(self):
        if os.path.exists('config.json'):
            with open('config.json', 'r') as config_file:
                config_data = json.load(config_file)
                self.config_input.text = json.dumps(config_data, indent=4)
        else:
            # 如果没有配置文件，可以设置一个默认值
            pass

    def start_foreground_service(self):
        PythonService = autoclass('org.kivy.android.PythonService')
        service = PythonService.mService
        service.startForeground(1, service.createNotification("TlsFragment", "Running..."))


    def save_config(self, instance):
        config_data = self.config_input.text
        # 将配置数据保存到 config.json 文件
        with open('config.json', 'w') as config_file:
            json.dump(config_data, config_file)

        # 提示用户保存成功
        print("Configuration saved successfully.")

if __name__ == '__main__':
    ProxyApp().run()
