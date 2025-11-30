from flask import Flask, render_template, request
from analyzer import analyze_policy

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Extract form data
        policy = {
            'min_length': int(request.form.get('min_length')),
            'require_special': 'require_special' in request.form,
            'require_upper': 'require_upper' in request.form,
            'require_rotation': 'require_rotation' in request.form,
            'rotation_days': request.form.get('rotation_days'),
            'allow_hints': 'allow_hints' in request.form
        }
        
        report = analyze_policy(policy)
        return render_template('report.html', report=report, policy=policy)
        
    return render_template('index.html')

if __name__ == '__main__':
    print("Starting Password Policy Analyzer...")
    app.run(debug=True, port=5000)
