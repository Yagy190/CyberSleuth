// CyberSleuth AI – Login Page
// Member 3: Frontend & Security Visualization
import { useState } from 'react'
import { Form, Input, Button, Card, Typography, Alert, Space } from 'antd'
import { LockOutlined, UserOutlined, SafetyCertificateOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

const { Title, Text } = Typography

export default function Login() {
  const { login } = useAuth()
  const navigate  = useNavigate()
  const [error, setError]     = useState('')
  const [loading, setLoading] = useState(false)

  const onFinish = async (values: { username: string; password: string }) => {
    setError('')
    setLoading(true)
    try {
      await login(values.username, values.password)
      navigate('/')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail ?? 'Login failed. Check your credentials.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#0d1117',
      }}
    >
      <Card
        style={{
          width: 380,
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 12,
        }}
      >
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          {/* Brand header */}
          <div style={{ textAlign: 'center' }}>
            <SafetyCertificateOutlined style={{ fontSize: 40, color: '#1677ff' }} />
            <Title level={3} style={{ color: '#e6edf3', marginTop: 8, marginBottom: 0 }}>
              CyberSleuth AI
            </Title>
            <Text style={{ color: '#8b949e', fontSize: 13 }}>
              Autonomous Security Investigation Platform
            </Text>
          </div>

          {error && <Alert type="error" message={error} showIcon />}

          <Form layout="vertical" onFinish={onFinish} size="large">
            <Form.Item
              name="username"
              rules={[{ required: true, message: 'Enter your username' }]}
            >
              <Input
                prefix={<UserOutlined style={{ color: '#8b949e' }} />}
                placeholder="Username"
                style={{ background: '#0d1117', borderColor: '#30363d', color: '#e6edf3' }}
              />
            </Form.Item>

            <Form.Item
              name="password"
              rules={[{ required: true, message: 'Enter your password' }]}
            >
              <Input.Password
                prefix={<LockOutlined style={{ color: '#8b949e' }} />}
                placeholder="Password"
                style={{ background: '#0d1117', borderColor: '#30363d', color: '#e6edf3' }}
              />
            </Form.Item>

            <Form.Item style={{ marginBottom: 0 }}>
              <Button type="primary" htmlType="submit" block loading={loading}>
                Sign In
              </Button>
            </Form.Item>
          </Form>

          <Text style={{ color: '#6e7681', fontSize: 12, textAlign: 'center', display: 'block' }}>
            Default: admin / admin123 (change in production)
          </Text>
        </Space>
      </Card>
    </div>
  )
}
