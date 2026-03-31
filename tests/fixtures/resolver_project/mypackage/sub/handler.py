from ..utils import helper
from . import constants

def handle(request):
    data = helper(request.input)
    cursor.execute(data)
    return data
