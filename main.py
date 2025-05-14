from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.metrics import dp
from jnius import autoclass
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
            import jnius
            Context = jnius.autoclass('android.content.Context')
            Intent = jnius.autoclass('android.content.Intent')
            PendingIntent = jnius.autoclass('android.app.PendingIntent')
            AndroidString = jnius.autoclass('java.lang.String')
            NotificationBuilder = jnius.autoclass('android.app.Notification$Builder')
            Notification = jnius.autoclass('android.app.Notification')
            service_name = 'ProxyService'
            package_name = 'org.maoist2009.tlsfragment'
            service = jnius.autoclass('org.kivy.android.PythonService').mService
            # Previous version of Kivy had a reference to the service like below.
            #service = jnius.autoclass('{}.Service{}'.format(package_name, service_name)).mService
            PythonActivity = jnius.autoclass('org.kivy.android' + '.PythonActivity')
            notification_service = service.getSystemService(
                Context.NOTIFICATION_SERVICE)
            app_context = service.getApplication().getApplicationContext()
            notification_builder = NotificationBuilder(app_context)
            title = AndroidString("EzTunes".encode('utf-8'))
            message = AndroidString("Ready to play music.".encode('utf-8'))
            app_class = service.getApplication().getClass()
            notification_intent = Intent(app_context, PythonActivity)
            notification_intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP |
                Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_NEW_TASK)
            notification_intent.setAction(Intent.ACTION_MAIN)
            notification_intent.addCategory(Intent.CATEGORY_LAUNCHER)
            intent = PendingIntent.getActivity(service, 0, notification_intent, 0)
            notification_builder.setContentTitle(title)
            notification_builder.setContentText(message)
            notification_builder.setContentIntent(intent)
            Drawable = jnius.autoclass("{}.R$drawable".format(service.getPackageName()))
            icon = getattr(Drawable, 'icon')
            notification_builder.setSmallIcon(icon)
            notification_builder.setAutoCancel(True)
            new_notification = notification_builder.getNotification()
            #Below sends the notification to the notification bar; nice but not a foreground service.
            #notification_service.notify(0, new_noti)
            service.startForeground(1, new_notification)
            
            print("Proxy service started")
            self.start_button.disabled = True
            self.stop_button.disabled = False
            
        except Exception as e:
            print(f"Failed to start service: {e}")
            import traceback
            traceback.print_exc()

    def stop_proxy_service(self, instance):
        """停止代理服务"""
        try:
            PythonService = autoclass('org.kivy.android.PythonService')
            service = PythonService.mService
            
            # 发送停止命令到服务
            service.stopService()
            
            print("Proxy service stopped")
            self.start_button.disabled = False
            self.stop_button.disabled = True
            
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

    def create_notification(self):
        """创建通知（与之前相同）"""
        try:
            Notification = autoclass('android.app.Notification')
            NotificationChannel = autoclass('android.app.NotificationChannel')
            NotificationManager = autoclass('android.app.NotificationManager')
            Context = autoclass('android.content.Context')
            Intent = autoclass('android.content.Intent')
            PendingIntent = autoclass('android.app.PendingIntent')
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            
            service = autoclass('org.kivy.android.PythonService').mService
            context = service.getApplicationContext()
            
            channel_id = "tls_fragment_channel"
            channel_name = "TlsFragment Service"
            channel_importance = NotificationManager.IMPORTANCE_LOW
            
            if service.getApplicationInfo().targetSdkVersion >= 26:
                channel = NotificationChannel(channel_id, channel_name, channel_importance)
                manager = context.getSystemService(Context.NOTIFICATION_SERVICE)
                manager.createNotificationChannel(channel)
            
            intent = Intent(context, PythonActivity)
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            pending_intent = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_IMMUTABLE
            )
            
            builder = Notification.Builder(context, channel_id)
            builder.setContentTitle("TlsFragment")
            builder.setContentText("Proxy server running...")
            builder.setSmallIcon(context.getApplicationInfo().icon)
            builder.setContentIntent(pending_intent)
            builder.setOngoing(True)
            
            if service.getApplicationInfo().targetSdkVersion >= 16:
                return builder.build()
            else:
                return builder.getNotification()
                
        except Exception as e:
            print(f"Error creating notification: {e}")
            return None

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