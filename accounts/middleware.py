# middleware.py
from django.utils.deprecation import MiddlewareMixin

class SetOpenerPolicyMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Embedder-Policy'] = 'require-corp'  
        return response
