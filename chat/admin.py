from django.contrib import admin
from .models import Profile, Room, Message, Reaction

# Register your models here.
admin.site.register(Profile)
admin.site.register(Room)
admin.site.register(Message)
admin.site.register(Reaction)