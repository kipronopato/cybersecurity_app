from django import forms

class PredictionForm(forms.Form):
    destination_port = forms.FloatField(label='Destination Port', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    flow_iat_min = forms.FloatField(label='Flow IAT Min', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    init_win_bytes_forward = forms.FloatField(label='Init Win Bytes Forward', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    flow_duration = forms.FloatField(label='Flow Duration', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    total_length_of_fwd_packets = forms.FloatField(label='Total Length of Fwd Packets', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    init_win_bytes_backward = forms.FloatField(label='Init Win Bytes Backward', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    flow_bytes_s = forms.FloatField(label='Flow Bytes/s', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    fwd_iat_min = forms.FloatField(label='Fwd IAT Min', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    bwd_packets_s = forms.FloatField(label='Bwd Packets/s', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    fwd_packet_length_max = forms.FloatField(label='Fwd Packet Length Max', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    bwd_iat_total = forms.FloatField(label='Bwd IAT Total', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    fin_flag_count = forms.FloatField(label='FIN Flag Count', widget=forms.NumberInput(attrs={'class': 'form-control'}))
    flow_packets_s = forms.FloatField(label='Flow Packets/s', widget=forms.NumberInput(attrs={'class': 'form-control'}))