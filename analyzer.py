def analyze_policy(policy):
    """
    Analyzes a password policy dictionary and returns a score and list of findings.
    
    Policy keys expected:
    - min_length (int)
    - require_special (bool)
    - require_upper (bool)
    - require_rotation (bool)
    - rotation_days (int)
    - allow_hints (bool)
    """
    score = 100
    findings = []
    
    # 1. Length Check
    # NIST 800-63B: Minimum 8 characters for user-generated passwords.
    min_len = int(policy.get('min_length', 0))
    if min_len < 8:
        score -= 40
        findings.append({
            'status': 'FAIL',
            'title': 'Minimum Length Too Short',
            'desc': f'Your policy allows {min_len} character passwords. NIST 800-63B recommends a minimum of 8 characters for user-generated passwords.',
            'recommendation': 'Increase minimum length to at least 8 (preferably 12+).'
        })
    elif min_len >= 12:
        findings.append({
            'status': 'PASS',
            'title': 'Strong Minimum Length',
            'desc': 'Requiring 12+ characters is excellent practice.',
            'recommendation': 'Keep it up!'
        })
    else:
        findings.append({
            'status': 'WARN',
            'title': 'Acceptable Minimum Length',
            'desc': '8 characters is the bare minimum. Longer is better.',
            'recommendation': 'Consider increasing to 10 or 12.'
        })

    # 2. Complexity Rules (Composition)
    # NIST 800-63B: "Verifiers SHOULD NOT impose other composition rules (e.g., requiring mixtures of different character types)"
    if policy.get('require_special') or policy.get('require_upper'):
        score -= 10
        findings.append({
            'status': 'WARN',
            'title': 'Unnecessary Complexity Rules',
            'desc': 'Forcing special characters or uppercase often leads to predictable patterns (e.g., "Password1!"). NIST recommends checking against compromised password lists instead of enforcing composition rules.',
            'recommendation': 'Remove mandatory character type requirements. Focus on length and blacklisting common passwords.'
        })
    else:
        findings.append({
            'status': 'PASS',
            'title': 'Modern Complexity Approach',
            'desc': 'Not forcing arbitrary complexity rules aligns with modern NIST standards.',
            'recommendation': 'Ensure you are blocking commonly used passwords (e.g., "password", "123456") on the backend.'
        })

    # 3. Rotation (Expiration)
    # NIST 800-63B: "Verifiers SHOULD NOT require memorized secrets to be changed arbitrarily (e.g., periodically)"
    if policy.get('require_rotation'):
        score -= 30
        days = policy.get('rotation_days', 90)
        findings.append({
            'status': 'FAIL',
            'title': 'Mandatory Rotation is Harmful',
            'desc': f'Forcing users to change passwords every {days} days causes "password fatigue". Users simply increment a number (Pass1, Pass2) or write it down.',
            'recommendation': 'Eliminate periodic password expiration. Only force a change if there is evidence of compromise.'
        })
    else:
        findings.append({
            'status': 'PASS',
            'title': 'No Arbitrary Rotation',
            'desc': 'Excellent. Avoiding forced rotation prevents password fatigue and weak patterns.',
            'recommendation': 'Maintain this policy.'
        })

    # 4. Password Hints
    # NIST 800-63B: "Verifiers SHALL NOT permit the subscriber to store a hint that is accessible to an unauthenticated claimant"
    if policy.get('allow_hints'):
        score -= 20
        findings.append({
            'status': 'FAIL',
            'title': 'Password Hints Enabled',
            'desc': 'Hints often reveal the password or make it easier to guess (e.g., "My dog\'s name").',
            'recommendation': 'Disable password hints completely.'
        })
    else:
        findings.append({
            'status': 'PASS',
            'title': 'No Password Hints',
            'desc': 'Correct. Hints are a security vulnerability.',
            'recommendation': 'None.'
        })

    # Calculate Grade
    if score >= 90: grade = 'A'
    elif score >= 80: grade = 'B'
    elif score >= 70: grade = 'C'
    elif score >= 60: grade = 'D'
    else: grade = 'F'

    return {
        'score': max(0, score),
        'grade': grade,
        'findings': findings
    }
