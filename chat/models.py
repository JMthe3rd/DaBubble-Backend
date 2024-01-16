from datetime import date
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

# Create your models here.
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.CharField(null=True, max_length=200)
    birth_date = models.DateField(null=True, blank=True)    
    profile_pic = models.ImageField(default='default.jpg', upload_to='profiles_pics')
    online = models.BooleanField(default=False)

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    instance.profile.save()

class Room(models.Model):
    roomName = models.CharField(max_length=100)
    description = models.CharField(max_length=255)
    created_by = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='room_createdby_set')
    created_at = models.DateField(default=date.today)

class Message(models.Model): 
    sender = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='directMessage_sender_set')
    message = models.CharField(max_length=255)
    reciever = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='directMessage_reciever_set', default=None, blank=True, null=True)
    created_at = models.DateField(default=date.today)
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='roomMessage_room_set', default=None, blank=True, null=True)

class Reaction(models.Model):
    sender = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name='reaction_sender_set')
    message = models.CharField(max_length=10)
    reacted_to = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='reaction_message_set',)