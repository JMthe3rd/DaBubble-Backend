from django.shortcuts import get_object_or_404, render
from rest_framework.authtoken.views import ObtainAuthToken, APIView
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .models import Room, Profile, Message, Reaction
from rest_framework import status
from .serializer import MessageSerializer, RoomSerializer, ReactionSerializer

# Create your views here.

class LoginView(ObtainAuthToken):
        def post(self, request, *args, **kwargs):
            serializer = self.serializer_class(data=request.data,
                                            context={'request': request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            user = User.objects.get(pk=user.pk)
            user.profile.online = True
            user.save()
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email
            })


class create_User(APIView):
    def post(self, request):
            if request.data['password'] == request.data['password_repeat']:
                user = User.objects.create_user(username=request.data['username'], email=request.data['email'], password=request.data['password'])
                user.save()
                return Response({'success': 'Benutzer erfolgreich erstellt.'}, status=status.HTTP_201_CREATED)
            else :
                return Response({'success': 'Passwörter stimmen nicht überein.'})
            

class logout_view(APIView):
      authentication_classes = [TokenAuthentication]
      permission_classes = [IsAuthenticated]

      def post(self, request, format=None):
        try:
            request.user.profile.online = False
            request.user.save()
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RoomMessage_View(APIView):
      authentication_classes = [TokenAuthentication]
      permission_classes = [IsAuthenticated]

      def get(self, request, format=None):
            messages = Message.objects.filter(room=request.data['room'])
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data)
      
      def post(self, request, format=None): 
            room_id = request.data.get('room')
            room = get_object_or_404(Room, pk=room_id)
            message = Message.objects.create(sender=request.user, message=request.data['message'], room=room)
            message.save()
            return Response({'success': 'Nachricht erfolgreich an Raum abgeschickt.'}, status=status.HTTP_201_CREATED)
      
class DirectMessage_View(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
            messages = Message.objects.filter(sender=request.user)
            serializer = MessageSerializer(messages, many=True)
            return Response(serializer.data)
    
    def post(self, request, format=None): 
              reciever_id = request.data.get('reciever')
              reciever = get_object_or_404(User, pk=reciever_id)
              message = Message.objects.create(sender=request.user, message=request.data['message'], reciever=reciever)
              message.save()
              return Response({'success': 'Nachricht erfolgreich abgeschickt.'}, status=status.HTTP_201_CREATED)

      
class Room_View(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        rooms = Room.objects.all()
        serializer = RoomSerializer(rooms, many=True)
        return Response(serializer.data)
    
    def post(sefl, request, format=None):
        try:
            room = Room.objects.create(roomName=request.data['roomName'], description=request.data['description'], created_by=request.user)
            room.save()
            return Response({'success': 'Raum erfolgreich erstellt.'}, status=status.HTTP_201_CREATED)
        except:
            return Response({'success': 'Fehler'})