const baseUrl = '/api/auth';

async function request(path, body) {
  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new Error('Unable to reach the authentication server. Start the backend with `npm run server` or `npm run dev:all`.');
  }

  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch (error) {
    throw new Error(
      `Authentication server returned an invalid response. This often means the auth backend is not running or the request path is wrong.`
    );
  }

  if (!response.ok) {
    throw new Error(data.error || 'Authentication request failed.');
  }

  return data;
}

export function register(payload) {
  return request('/register', payload);
}

export function login(payload) {
  return request('/login', payload);
}

export function verifyOtp(payload) {
  return request('/verify-otp', payload);
}
