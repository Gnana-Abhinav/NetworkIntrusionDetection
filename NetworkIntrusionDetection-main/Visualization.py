import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.graph_objs as go
import pickle
import numpy as np


# Load the CSV data

I = 0
df = pd.read_csv('record_self.csv')  # Replace 'your_data.csv' with the actual file path
df.drop(['service'], axis=1, inplace=True)



protocol_map = np.load('protocol_map.npy', allow_pickle=True).item()
flag_map = np.load('flag_map.npy', allow_pickle=True).item()
# load the model from disk
loaded_model = pickle.load(open('model.pkl', 'rb'))

# Get the last 100 rows
for i, p in enumerate(df.protocol_type.unique()):
        df.loc[df.protocol_type == p, 'protocol_type'] = protocol_map.get(p, 3)

    # Map the flags to integers
for i, p in enumerate(df.status_flag.unique()):
    df.loc[df.status_flag == p, 'status_flag'] = flag_map.get(p, 11)

y_pred = loaded_model.predict(df)
df['predictions'] = y_pred
df.reset_index(inplace=True)  # Reset index and make it a column


# Initialize the Dash app
app = dash.Dash(__name__)

# Define the layout of the app
app.layout = html.Div([
    dcc.Graph(id='prediction-plot' ),
    dcc.Graph(id='src-bytes-plot'),
    dcc.Graph(id='dst-bytes-plot'),
    dcc.Graph(id='status-flag-plot'),
    dcc.Interval(
        id='interval-component',
        interval=1*1000,  # Update every 1 second (adjust as needed)
        n_intervals=0
    )
])

# Update plots on interval update
@app.callback(
    [Output('prediction-plot', 'figure'),
     Output('src-bytes-plot', 'figure'),
     Output('dst-bytes-plot', 'figure'),
     Output('status-flag-plot', 'figure')],
    [Input('interval-component', 'n_intervals')]
)
def update_plots(n):
    # Filter the data for the latest entries (adjust this logic as needed)
    #ith recent_data of df in recent data

    
    global I
    if(I < df.shape[0]):
        recent_data = df.head(I)
        I += 1
    else:
        recent_data = df.tail(1)
        I = 0
    # Extract the index values as time values (assuming the index represents time)
    time_values = recent_data['index']

    # Filter columns of interest
    pred_values = recent_data['predictions']
    src_bytes_values = recent_data['src_bytes']
    dst_bytes_values = recent_data['dst_bytes']
    status_flag_values = recent_data['status_flag']

    # Highlight points where prediction is 1
    pred_color = ['#FF0000' if pred == 1 else '#0000FF' for pred in pred_values]

    # Create Plotly traces
    # pred_trace = go.Scatter(x=time_values, y=pred_values, mode='lines', marker=dict(color=pred_color), name='Predictions vs Time')

    # Create a line plot for predictions with red color for attacks and blue color for normal
    pred_trace = go.Scatter(x=time_values, y=pred_values, mode='lines', marker=dict(color=pred_color), name='Predictions vs Time')
    src_bytes_trace = go.Scatter(x=time_values, y=src_bytes_values, mode='lines', name='src_bytes vs Time')
    dst_bytes_trace = go.Scatter(x=time_values, y=dst_bytes_values, mode='lines', name='dst_bytes vs Time')
    status_flag_trace = go.Scatter(x=time_values, y=status_flag_values, mode='lines', name='status_flag vs Time')

    # Create Plotly figures
    prediction_plot = {'data': [pred_trace], 'layout': {'title': 'Predictions vs Time'}}
    src_bytes_plot = {'data': [src_bytes_trace], 'layout': {'title': 'src_bytes vs Time'}}
    dst_bytes_plot = {'data': [dst_bytes_trace], 'layout': {'title': 'dst_bytes vs Time'}}
    status_flag_plot = {'data': [status_flag_trace], 'layout': {'title': 'status_flag vs Time'}}

    return prediction_plot, src_bytes_plot, dst_bytes_plot, status_flag_plot

# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)


