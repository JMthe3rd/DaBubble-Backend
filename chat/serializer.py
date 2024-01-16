from rest_framework import serializers
from .models import Room, Message, Profile, Reaction

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = '__all__'

class MessageSerializer(serializers.ModelSerializer):
    room = RoomSerializer()
    class Meta: 
        model = Message
        fields = '__all__'

class ReactionSerializer(serializers.ModelSerializer):
    reacted_to = MessageSerializer()
    class Meta: 
        model = Reaction
        fields = '__all__'