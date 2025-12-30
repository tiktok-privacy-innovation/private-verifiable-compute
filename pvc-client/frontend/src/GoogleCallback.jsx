// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
function GoogleCallback() {
    const navigate = useNavigate();

    useEffect(() => {
        const handleAuthCallback = async () => {
            const hash = window.location.hash.substring(1);
            const params = new URLSearchParams(hash);
            const idToken = params.get('id_token');
            const error = params.get('error');
            if (error) {
                console.error('OAuth Error:', error);
                navigate('/');
                return;
            }
            try {
                console.log('Successfully received id token:', idToken);
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        "idToken": idToken
                    }),
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `Backend returned status ${response.status}`);
                }

                navigate('/', { replace: true });
            } catch (err) {
                console.error('Failed to send idToken to backend:', err);
                navigate('/');
            }
        }
        handleAuthCallback();
    }, [navigate]);
    return (
        <div className="app-login">
            <div className="login-container">
                <h2>Authenticating with Google...</h2>
                <p>Please wait, you will be redirected shortly.</p>
                <div className="loading-spinner"></div>
            </div>
        </div>
    );
}
export default GoogleCallback;