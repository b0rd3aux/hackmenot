// Sample JSX file for testing
import React from 'react';

function UserCard({ user }) {
    const profileUrl = `/users/${user.id}`;

    return (
        <div className="user-card">
            <h2>{user.name}</h2>
            <a href={profileUrl}>View Profile</a>
            <div dangerouslySetInnerHTML={{ __html: user.bio }} />
        </div>
    );
}

export const Badge = ({ type, label }) => {
    return <span className={`badge badge-${type}`}>{label}</span>;
};

export default UserCard;
