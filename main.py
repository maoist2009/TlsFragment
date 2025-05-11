from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from jnius import autoclass
import os
import json
from src.tls_fragment.cli import start_server, stop_server

class ProxyApp(App):
    def build(self):
        print("Building UI")
        layout = BoxLayout(orientation='vertical')

        self.start_button = Button(text='Start Proxy')
        self.start_button.bind(on_press=self.start_proxy)
        layout.add_widget(self.start_button)

        self.stop_button = Button(text='Stop Proxy')
        self.stop_button.bind(on_press=self.stop_proxy)
        layout.add_widget(self.stop_button)

        self.save_button = Button(text='Save Config')
        self.save_button.bind(on_press=self.save_config)
        layout.add_widget(self.save_button)

        self.config_input = TextInput(hint_text='Edit config.json', multiline=True)
        layout.add_widget(self.config_input)

        print("UI built successfully")
        return layout

    def on_start(self):
        # 在应用完全启动后加载配置和启动服务
        self.load_config()
        self.start_foreground_service()

    def start_proxy(self, instance):
        try:
            start_server(block=False)
            print("Proxy server started")
        except Exception as e:
            print(f"Failed to start proxy: {e}")

    def stop_proxy(self, instance):
        try:
            stop_server(wait_for_stop=True)
            print("Proxy server stopped")
        except Exception as e:
            print(f"Failed to stop proxy: {e}")

    def load_config(self):
        config_path = 'config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as config_file:
                    config_data = json.load(config_file)
                    self.config_input.text = json.dumps(config_data, indent=4)
                print("Config loaded successfully")
            except Exception as e:
                print(f"Failed to load config: {e}")
        else:
            print("Config file not found, using empty config")
            self.config_input.text = "{}"

    def start_foreground_service(self):
        try:
            PythonService = autoclass('org.kivy.android.PythonService')
            service = PythonService.mService
            service.startForeground(1, service.createNotification("TlsFragment", "Running..."))
            print("Foreground service started")
        except Exception as e:
            print(f"Failed to start foreground service: {e}")

    def save_config(self, instance):
        try:
            config_data = json.loads(self.config_input.text)
            with open('config.json', 'w') as config_file:
                json.dump(config_data, config_file, indent=4)
            print("Configuration saved successfully.")
        except json.JSONDecodeError:
            print("Invalid JSON format, please check your configuration")
        except Exception as e:
            print(f"Failed to save config: {e}")

if __name__ == '__main__':
    ProxyApp().run()