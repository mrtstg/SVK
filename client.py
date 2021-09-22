import api
import requests
import random
import json
import threading
import os
import re
import time
from queue import Queue
import cherrypy

def reboot(f):

    def _reboot(*args, **kwargs):
        while True:
            try:
                return f(*args, **kwargs)
            except Exception as e:
                print(e)

    return _reboot


def word_difference(word1, word2) -> float:
    return (1 - damerau_levenshtein_distance(word1, word2) / len(word1)) * 100


def damerau_levenshtein_distance(s1, s2):
    d = {}
    lenstr1 = len(s1)
    lenstr2 = len(s2)
    for i in range(-1, lenstr1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, lenstr2 + 1):
        d[(-1, j)] = j + 1
    for i in range(lenstr1):
        for j in range(lenstr2):
            if s1[i] == s2[j]:
                cost = 0
            else:
                cost = 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,  # deletion
                d[(i, j - 1)] + 1,  # insertion
                d[(i - 1, j - 1)] + cost,  # substitution
            )
            if i and j and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[i - 2, j - 2] + cost)  # transposition
    return d[lenstr1 - 1, lenstr2 - 1]


class Event:
    def __init__(self, event_info):
        self.event = event_info
        self.type = event_info['type']
        self.object = event_info['object']
    
    def __getattr__(self, attrname):
        if attrname in self.__dict__:
            return self.__dict__[attrname]
        
        if attrname in self.object:
            return self.object[attrname]
        
        if attrname in self.event:
            return self.event[attrname]
        
        raise AttributeError(f'{attrname} is not found in event info.')


class CallbackMessage(Event):
    def __init__(self, event_info):
        super().__init__(event_info=event_info)
        payload = self.object['payload']
        self.text = ''
        if 'command' in payload:
            self.text = payload['command']
        self.from_payload = False
        self.callback = True
        self.from_id = self.object['user_id']
        self.peer_id = self.object['peer_id']
        self.chat_id = max(0, self.peer_id - 2e9)
        self.from_chat = self.chat_id > 0

        self.message_words = self.text.split(' ')
        self.command = self.message_words[0].lower()

class Message(Event):
    def __init__(self, event_info):
        super().__init__(event_info=event_info)
        self.message = self.event['object']['message']
        self.from_payload = False
        self.callback = False
        self.text = self.message['text']
        if 'payload' in self.message:
            payload = json.loads(self.message['payload'])
            if 'command' in payload:
                self.text = str(payload['command'])
                self.from_payload = True
        group_push_match = re.findall(r'^[club[0-9]{1,}\|.{1,}\] (.{1,})', self.text)
        if group_push_match:
            self.text = group_push_match[0]
        self.from_id = self.message['from_id']
        self.peer_id = self.message['peer_id']
        self.chat_id = max(0, self.peer_id - 2e9)
        self.from_chat = self.chat_id > 0

        self.message_words = self.text.split(' ')
        self.command = self.message_words[0].lower()
    
    def __getattr__(self, attrname):
        if attrname in self.__dict__:
            return self.__dict__[attrname]

        if attrname in self.message:
            return self.message[attrname]
        
        if attrname in self.object:
            return self.object[attrname]
        
        raise AttributeError(f'{attrname} is not found in event info.')


class Handler:
    def __init__(self, function, event_type, error_handler = None):
        self.function = function
        self.event_type = event_type
        self.error_handler = error_handler
    
    def __call__(self, event):
        if self.event_type == event.type:
            try:
                self.function(event)
            except Exception as e:
                if self.error_handler is None:
                    raise Exception(e)
                else:
                    self.error_handler(event, e)


class MessageHandler(Handler):
    def __init__(self, function, commands, regex, prefix, predict, _filter, 
                message_type, error_handler = None):
        super().__init__(
            function=function,
            event_type='message_new',
            error_handler=error_handler
        )
        self.message_type = message_type
        self.prefix = prefix
        self.predict = predict
        self.commands = list(map(lambda x: self.prefix + x, commands if isinstance(commands, list) else [commands]))
        self.regex = regex
        self.filter = _filter
    
    def __call__(self, message):
        try:
            if self.regex is None:
                self.function(message)
            else:
                self.function(message, re.findall(self.regex, message.text, flags=re.IGNORECASE)[0])
        except Exception as e:
            if self.error_handler is None:
                raise Exception(e)
            else:
                self.error_handler(message, e)

    def check_filters(self, message):
        if self.filter is not None:
            if not self.filter(message):
                return False
        
        if self.regex is None and not self.commands:
            return True
        
        if message.from_payload and 'payload' not in self.message_type:
            return False
        
        if message.callback and 'callback' not in self.message_type:
            return False
        
        if not message.from_payload and not message.callback and 'text' not in self.message_type:
            return False
        
        if self.commands:
            if message.command in self.commands:
                return True
            elif self.predict:
                return any(
                    word_difference(command_variant, message.command) >= 80
                    and message.command.find(self.prefix) == 0
                    for command_variant in self.commands
                )
        else:
            if re.findall(self.regex, message.text, flags=re.IGNORECASE):
                return True

        return False


class ActionHandler(MessageHandler):
    def __init__(self, action_type, function, _filter, error_handler = None):
        super().__init__(
            function=function,
            commands=[],
            regex=None,
            predict=False,
            prefix='',
            _filter=_filter,
            message_type=['text'],
            error_handler=error_handler
        )
        self.action_type = action_type if isinstance(action_type, list) else [action_type]
    
    def __call__(self, message):
        try:
            if (
                'action' in message.message
                and message.message['action']['type'] in self.action_type
            ):
                message.action = message.message['action']
                self.function(message)
        except Exception as e:
            if self.error_handler is None:
                raise Exception(e)
            else:
                self.error_handler(message, e)


class InviteHandler(ActionHandler):
    def __init__(self, function, _filter, error_handler = None):
        super().__init__(
            action_type=['chat_invite_user', 'chat_invite_user_by_link'],
            function=function,
            _filter=_filter,
            error_handler=error_handler
        )


class KickHandler(ActionHandler):
    def __init__(self, function, _filter, error_handler = None):
        super().__init__(
            action_type='chat_kick_user',
            function=function,
            _filter=_filter,
            error_handler=error_handler
        )


class ClientBase:
    def __init__(self, access_token: str, api_timeout: int = 5, api_version: str = '5.131',
                handle_callback = False, handle_payload = True, predict_commands = True, handle_bots = False,
                message_error_handler = None, other_error_handler = None):
        self._token = access_token
        self.api = api.ApiClient(access_token=access_token, timeout=api_timeout, version=api_version)
        self.group_id = self.api.groups.getById()[0]['id']
        self.message_handlers = []
        self.any_message_handlers = []
        self.handlers = []
        self.predict_commands = predict_commands
        self.handle_bots = handle_bots
        self.default_message_type = ['text']
        if handle_callback:
            self.default_message_type.append('callback')
        if handle_payload:
            self.default_message_type.append('payload')
        self.message_error_handler = message_error_handler
        self.other_error_handler = other_error_handler
    
    def get_api(self):
        return self.api
    
    def _get_event(self, event_info):
        if event_info['type'] == 'message_new':
            return Message(event_info)
        elif event_info['type'] == 'message_event':
            return CallbackMessage(event_info)
        else:
            return Event(event_info)
    
    def message_handler(self, regex = None, commands = [], prefix = '', predict = True, 
                        message_type = None, _filter = None):
        if message_type is None:
            message_type = self.default_message_type

        def _message_handler(f):
            handler = MessageHandler(
                    function=f,
                    commands=commands,
                    regex=regex,
                    prefix=prefix,
                    predict=predict and self.predict_commands,
                    _filter=_filter,
                    error_handler=self.message_error_handler,
                    message_type=message_type
                )
            if regex is None and not commands:
                self.any_message_handlers.append(handler)
            else:
                self.message_handlers.append(handler)
            return f

        return _message_handler
    
    def invite_handler(self, _filter = None):

        def _invite_handler(f):
            handler = InviteHandler(
                function=f,
                _filter=_filter,
                error_handler=self.message_error_handler
            )
            self.any_message_handlers.append(handler)
            return f

        return _invite_handler
    
    def kick_handler(self, _filter = None):

        def _kick_handler(f):
            handler = KickHandler(
                function=f,
                _filter=_filter,
                error_handler=self.message_error_handler
            )
            self.any_message_handlers.append(handler)
            return f

        return _kick_handler
    
    def action_handler(self, action_type, _filter = None):

        def _action_handler(f):
            handler = ActionHandler(
                action_type=action_type,
                function=f,
                _filter=_filter,
                error_handler=self.message_error_handler
            )
            self.any_message_handlers.append(handler)
            return f
        
        return _action_handler

    def custom_handler(self, event_type):
        
        def _custom_handler(f):
            self.handlers.append(
                Handler(
                    function=f,
                    event_type=event_type,
                    error_handler=self.other_error_handler
                )
            )
            return f

        return _custom_handler
    
    # TODO: придумать лучше костыль для обработчика всех сообщений
    def _notify_message_handlers(self, message):
        # TODO: было бы неплохо и этот костыль убрать
        if message.from_id < 0 and not self.handle_bots:
            return

        for handler in self.any_message_handlers:
            if handler.check_filters(message):
                handler(message)
        
        for handler in self.message_handlers:
            if handler.check_filters(message):
                handler(message)
                break
    
    def _notify_event_handlers(self, event):
        for handler in self.handlers:
            if handler.event_type == event.type:
                handler(event)
    
    def _notify_handlers(self, event):
        if event.type in ['message_new', 'message_event']:
            self._notify_message_handlers(event)
        else:
            self._notify_event_handlers(event)
    
    def reply(self, message, text, **kwargs):
        self.send_message(
            peer_id=message.peer_id,
            text=text,
            **kwargs
        )
    
    def split_string_by_length(self, string, length=4096):
        return [string[i: i + length] for i in range(0, len(string), length)]
    
    def split_string_by_symbol(self, string, split_symbol = '\n', length = 4096):
        string_parts = string.split(split_symbol)
        splitted_string = [""]
        for part in string_parts:
            if len(f'{splitted_string[-1]}{part}{split_symbol}') > length and splitted_string[-1] != '':
                splitted_string.append("")
            if len(part) + len(split_symbol) > length:
                splitted_part = self.split_string_by_length(part + split_symbol, length=length)
                if splitted_string[-1] == '':
                    splitted_string[-1] += splitted_part[0]
                    splitted_part = splitted_part[1:]
                splitted_string += splitted_part
            else:    
                splitted_string[-1] += f"{part}{split_symbol}"
        return splitted_string

    def send_message(self, peer_id, text, split_symbol = '\n', **kwargs):
        messages = self.split_string_by_symbol(
            string=text,
            split_symbol=split_symbol
        )
        for message in messages:
            self.api.messages.send(
                peer_id=peer_id,
                message=message,
                random_id=random.randint(-2147483648, 2147483647),
                **kwargs
            )
            if len(messages) > 1:
                time.sleep(0.1)
    
    def upload_photo(self, path = None, abspath = None, delete_after = True):
        path = os.path.join(os.getcwd(), path) if path is not None else abspath
        if not os.path.exists(path):
            raise FileNotFoundError('File not found')
        upload_url = self.api.photos.getMessagesUploadServer(peer_id=0)['upload_url']
        upload_request = requests.post(upload_url, files={'photo': open(path, 'rb')}).json()
        attachment_info = self.api.photos.saveMessagesPhoto(
            photo=upload_request['photo'],
            server=upload_request['server'],
            hash=upload_request['hash']
        )[0]
        if delete_after:
            os.remove(path)
        return f'photo{attachment_info["owner_id"]}_{attachment_info["id"]}'
    
    def upload_photos(self, path_list, delete_after = True):
        return [
            self.upload_photo(path=path, delete_after=delete_after)
            for path in path_list
        ]
    
    def edit_message(self, message, text, **kwargs):
        self.api.messages.edit(
            peer_id=message.peer_id,
            message=text,
            conversation_message_id=message.conversation_message_id,
            **kwargs
        )

    def show_snackbar(self, message, text):
        event_data = {
                'type': 'show_snackbar',
                'text': text
        }
        self._reply_callback_message(message, event_data)
    
    def open_link(self, message, url):
        event_data = {
            'type': 'open_link',
            'url': url
        }
        self._reply_callback_message(message, event_data)
    
    def open_app(self, message, app_id, app_hash, owner_id = None):
        event_data = {
            'type': 'open_app',
            'app_id': app_id,
            'owner_id': owner_id,
            'hash': app_hash
        }
        self._reply_callback_message(message, event_data)
    
    def _reply_callback_message(self, message, event_data):
        if not message.callback:
            raise Exception('Incorrect object - message must be CallbackMessage')
        
        self.api.messages.sendMessageEventAnswer(
            event_id=message.event_id,
            user_id=message.from_id,
            peer_id=message.peer_id,
            event_data=json.dumps(event_data, ensure_ascii=True)
        )


class LongpollThread(threading.Thread):
    def __init__(self, client, queue):
        threading.Thread.__init__(self)
        self.client = client
        self.queue = queue
    
    def run(self):
        while True:
            event = self.queue.get()
            self.client._notify_handlers(event)
            self.queue.task_done()


class Longpoll(ClientBase):
    def __init__(self, access_token: str, wait: int = 25, api_timeout: int = 5, api_version: str = '5.131',
                handle_callback = False, handle_payload = True, predict_commands = True, handle_bots = False,
                message_error_handler = None, other_error_handler = None):
        super().__init__(
            access_token=access_token,
            api_timeout=api_timeout,
            api_version=api_version,
            handle_callback=handle_callback,
            handle_payload=handle_payload,
            predict_commands=predict_commands,
            handle_bots=handle_bots,
            message_error_handler=message_error_handler,
            other_error_handler=other_error_handler
        )
        self.session = requests.Session()
        self.wait = wait
        
        self.get_longpoll_server()
    
    def get_longpoll_server(self, update_ts: bool = True):
        response = self.api.groups.getLongPollServer(group_id=self.group_id)

        self.key = response['key']
        self.server = response['server']
        if update_ts:
            self.ts = response['ts']
    
    def get_longpoll_events(self):
        values = {
            'act': 'a_check',
            'key': self.key,
            'ts': self.ts,
            'wait': self.wait
        }
        response = self.session.get(
            self.server,
            params=values,
            timeout=self.wait + 10
        ).json()

        if 'failed' not in response:
            self.ts = response['ts']
            return [self._get_event(update) for update in response['updates']]
        elif response['failed'] == 1:
            self.ts = response['ts']
        elif response['failed'] == 2:
            self.get_longpoll_server(update_ts=False)
        elif response['failed'] == 3:
            self.get_longpoll_server()
        
        return []

    @reboot
    def poll(self, multithreading: bool = False, threads_amount: int = 5):
        if multithreading:
            queue = Queue()

            for _ in range(threads_amount):
                t = LongpollThread(self, queue)
                t.setDaemon(True)
                t.start()
            
            while True:
                for event in self.get_longpoll_events():
                    queue.put(event)
        while True:
            for event in self.get_longpoll_events():
                self._notify_handlers(event)

def post_required(f):
    def _post_required(*args, **kwargs):
        if cherrypy.request.method != 'POST':
            return 'POST is required!'
        else:
            return f(*args, **kwargs)
    return _post_required

# ! на инструмент в cherrypy у меня выбивало ошибку, так что я просто написал свой
def get_args(f):
    def _get_args(*args, **kwargs):
        request_args = get_request_args(cherrypy.request)
        return f(*args, **kwargs, request_args=request_args)
    return _get_args

def get_request_args(request: cherrypy.request) -> dict:
    if request.method == 'POST':
        try:
            request_args = json.loads(cherrypy.request.body.read().decode('utf-8'))
        except:
            request_args = {}
    
    if request.method != 'POST' or request_args == {}:
        request_args = cherrypy.request.params
    
    return request_args


class CallbackServer:
    def __init__(self, group_id: int, secret: str, confirmation: str, notifyer, event_generator):
        self.group_id = group_id
        self.secret = secret
        self.confirmation = confirmation
        self.notifyer = notifyer
        self.event_generator = event_generator
    
    @get_args
    @post_required
    def callback(self, request_args, **kwargs):
        data = request_args
        # TODO: разные ответы на ошибки
        # TODO: протестить на работу callback-клиент
        # ! для регистронезависимости
        lower_headers = {
            i[0].lower(): i[1] for i in cherrypy.request.headers.items()
        }
        # TODO: убедиться что это работает
        if 'x-retry-counter' in lower_headers:
            print('TIMEOUT')
            return 'ok'

        if 'secret' not in data and self.secret != '':
            data['secret'] = '' 
        
        if 'group_id' not in data:
            data['group_id'] = 0
        
        if 'type' not in data:
            return 'ok'
        
        if self.secret != '' and data['secret'] != self.secret:
            return 'ok'
        
        if data['group_id'] != self.group_id:
            return 'ok'
        
        if data['type'] == 'confirmation':
            return self.confirmation
        
        self.notifyer(self.event_generator(data))
        return 'ok'
    callback.exposed = True

class Callback(ClientBase):
    def __init__(self, access_token: str, secret: str = '', confirmation: str = '', api_timeout: int = 5,
                api_version: str = "5.131", handle_callback = False, handle_payload = True, predict_commands = True,
                handle_bots = False, message_error_handler = None, other_error_handler = None):
        super().__init__(
            access_token=access_token,
            api_timeout=api_timeout,
            api_version=api_version,
            handle_callback=handle_callback,
            handle_payload=handle_payload,
            predict_commands=predict_commands,
            handle_bots=handle_bots,
            message_error_handler=message_error_handler,
            other_error_handler=other_error_handler
        )
        self.secret = secret
        self.confirmation = confirmation
        if self.confirmation == '':
            self.confirmation = self.api.groups.getCallbackConfirmationCode(
                group_id=self.group_id
            )['code']

        self.server = CallbackServer(
            group_id=self.group_id,
            secret=self.secret,
            confirmation=self.confirmation,
            notifyer=self._notify_handlers,
            event_generator=self._get_event
        )
        self.app = cherrypy.tree.mount(self.server, '/')
    
    def launch_server(self, ip: str, port: int):
        cherrypy.server.socket_host = ip
        cherrypy.server.socket_port = port
        cherrypy.config.update({
            'engine.autoreload.on': False
        })
        cherrypy.engine.start()
        cherrypy.engine.block()
    
    def get_server(self):
        return self.app