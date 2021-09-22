import requests

API_URL = 'https://api.vk.com/method/'

class ApiMethod:
    def __init__(self, client, method):
        self.client = client
        self.method = method
    
    def __call__(self, **kwargs):
        return self.client._call_method(self.method, values=kwargs)


class ApiMethods:
    def __init__(self, client, method_group):
        self.client = client
        self.method_group = method_group
    
    def __getattr__(self, attrname):
        if attrname in self.__dict__:
            return self.__dict__[attrname]

        return ApiMethod(self.client, '.'.join([self.method_group, attrname]))

class ApiClient:
    def __init__(self, access_token: str, timeout: int = 5, version: str = "5.131"):
        self.session = requests.Session()
        self._token = access_token
        self.timeout = timeout
        self.api_version = version

        self.session.headers['Accept'] = 'application/json'
        self.session.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    def __getattr__(self, attrname):
        if attrname in self.__dict__:
            return self.__dict__[attrname]

        return ApiMethods(self, attrname)
    
    def _call_method(self, *args, **kwargs):
        params = {'access_token': self._token, 'v': self.api_version}
        params.update(kwargs['values'])
        method_url = API_URL + args[0]
        response = self.session.post(
            url=method_url,
            params=params,
            timeout=self.timeout
        )

        response.raise_for_status()

        json_response = response.json()
        if 'error' in json_response:
            error_response = json_response['error']
            raise Exception(
                '[{}] {}. Request params: {}'.format(
                    error_response['error_code'],
                    error_response['error_msg'],
                    self._prettyfy_request_args(error_response['request_params'])
                )
            )

        return json_response['response']
    
    def _prettyfy_request_args(self, request_params):
        return '; '.join(
            ': '.join([param['key'], param['value']]) for param in request_params
        )